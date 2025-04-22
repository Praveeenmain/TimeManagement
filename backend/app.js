require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { connectToDb, getDb } = require("./db");
const cron = require('node-cron');
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const json2csv = require('json2csv').parse;
const { ObjectId } = require("mongodb");
const axios=require('axios')
const app = express();

app.use(cors({
    origin: 'http://localhost:8080', // 👈 specific origin, not '*'
    credentials: true,               // 👈 allow credentials like cookies
  }));
app.use(express.json());

let db;
connectToDb((err) => {
    if (err) {
        console.error("Error connecting to the database:", err);
        process.exit(1);
    } else {
        db = getDb();
        console.log("Connected to database.");
    }
});

function findMostCommonCategory(tasks) {
    const categoryCounts = {};
    tasks.forEach(task => {
        categoryCounts[task.category] = (categoryCounts[task.category] || 0) + 1;
    });
    return Object.keys(categoryCounts).reduce((a, b) => categoryCounts[a] > categoryCounts[b] ? a : b);
}

// --- Middleware to protect routes ---
function timeAiAuthMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1]; // Bearer token format
    if (!token) return res.status(401).json({ message: "No token provided" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next(); // Proceed to the next route handler
    } catch (err) {
        res.status(403).json({ message: "Invalid or expired token" });
    }
}

// --- Rate Limiting Middleware ---
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: "Too many requests from this IP, please try again later.",
});

app.use("/timeAi", limiter);

// --- Task Analysis function ---
function analyzeTasks(tasks) {
    // Validate if tasks is an array and has a length
    if (!Array.isArray(tasks) || tasks.length === 0) {
        throw new Error("No tasks to analyze");
    }

    // Example: Summarize tasks
    const categoryCount = tasks.reduce((acc, task) => {
        acc[task.category] = (acc[task.category] || 0) + 1;
        return acc;
    }, {});

    // Example: Filter overdue tasks based on startTime
    const overdueTasks = tasks.filter(task => {
        const taskStartTime = new Date(task.startTime);
        const currentTime = new Date();
        return taskStartTime < currentTime;  // Check if task is overdue (startTime before current time)
    });

    return {
        totalTasks: tasks.length,
        categories: categoryCount,
        overdueTasks: overdueTasks,
        overdueTasksCount: overdueTasks.length
    };
}

async function sendDeadlineReminder(userEmail, taskTitle, taskDeadline) {
    try {
        let transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        let mailOptions = {
            from: process.env.EMAIL_USER,
            to: userEmail,
            subject: 'Task Deadline Reminder',
            text: `Reminder: Your task "${taskTitle}" is due on ${taskDeadline}.`,
        };

        await transporter.sendMail(mailOptions);
        console.log("Reminder email sent to:", userEmail);
    } catch (error) {
        console.error("❌ Failed to send email:", error);
    }
}

cron.schedule('0 * * * *', async () => {
    try {
        const tasks = await db.collection("timeAitasks")
            .find({ userId: new ObjectId(req.user.id), completed: false })
            .toArray();

        // Check for tasks with a deadline within the next hour
        const urgentTasks = tasks.filter(task => {
            const deadline = new Date(task.deadline);
            return (deadline - new Date()) <= 3600000 && deadline > new Date();  // Within the next hour
        });

        // Send reminder email for urgent tasks
        for (const task of urgentTasks) {
            const user = await db.collection("timeAiuser").findOne({ _id: new ObjectId(req.user.id) });
            if (user) {
                await sendReminderEmail(user.email, task.title, task.deadline);
            }
        }

    } catch (err) {
        console.error("Error sending reminders:", err);
    }
});



// --- Hugging Face Recommendation ---
async function getTaskRecommendation(tasks) {
    try {
        const response = await axios.post(
            "https://api-inference.huggingface.co/models/facebook/bart-large-mnli",
            {
                inputs: tasks.map(task => task.title).join(" "),  // Combine task titles or descriptions
                parameters: {
                    candidate_labels: ["urgent", "low-priority", "work", "personal", "meeting", "reminder"]  // Example categories
                }
            },
            {
                headers: {
                    Authorization: `Bearer ${process.env.HUGGING_FACE_TOKEN}`,
                },
            }
        );
        return response.data;
    } catch (error) {
        console.error("Error getting recommendation:", error);
        return null;
    }
}

// --- Signup ---
app.post("/timeAi/signup", async (req, res) => {
    const { name, email, password } = req.body;
    const existing = await db.collection("timeAiuser").findOne({ email });
    if (existing) return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const result = await db.collection("timeAiuser").insertOne({ name, email, password: hashed });

    const token = jwt.sign({ id: result.insertedId, email }, process.env.JWT_SECRET);
    console.log("JWT Token after signup:", token);

    res.json({ message: "Signup successful", token });
});

// --- Login ---
app.post("/timeAi/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await db.collection("timeAiuser").findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET);
    res.json({ message: "Login successful",token });
});

// --- Add Task ---
app.post("/timeAi/task", timeAiAuthMiddleware, async (req, res) => {
    const { title, startTime, endTime, category, priority, deadline } = req.body;
    const task = {
        userId: new ObjectId(req.user.id),
        title,
        startTime,
        endTime,
        category,
        priority,
        completed: false,
        deadline,  // Save the deadline to the task
    };

    // Insert task into the database
    await db.collection("timeAitasks").insertOne(task);

    // Send a deadline reminder email to the user
    const user = await db.collection("timeAiuser").findOne({ _id: new ObjectId(req.user.id) });
    if (user) {
        await sendDeadlineReminder(user.email, title, deadline);
    }

    res.json({ message: "Task added and reminder email sent" });
});

app.get("/timeAi/task/:_id", timeAiAuthMiddleware, async (req, res) => {
    const { _id } = req.params;
    if (!ObjectId.isValid(_id)) return res.status(400).json({ error: "Invalid ID" });
    const task = await db.collection("timeAitasks").findOne({ _id: new ObjectId(_id), userId: new ObjectId(req.user.id) });
    if (!task) return res.status(404).json({ error: "Task not found" });
    res.json(task);
});

// --- Get Tasks ---
app.get("/timeAi/tasks", timeAiAuthMiddleware, async (req, res) => {
    const { priority } = req.query;
    const query = { userId: new ObjectId(req.user.id) };
    
    if (priority) query.priority = priority;  // Optional filtering by priority
    
    const tasks = await db.collection("timeAitasks").find(query).toArray();
    res.json(tasks);
});

// --- Edit Task ---
app.put("/timeAi/task/:_id", timeAiAuthMiddleware, async (req, res) => {
    const { _id } = req.params;
    
    // Validate ObjectId format
    if (!ObjectId.isValid(_id)) {
        return res.status(400).json({ error: "Invalid task ID" });
    }
    
    const taskId = new ObjectId(_id);
    const { title, startTime, endTime, category, priority } = req.body;
    
    try {
        // Log the exact query we're using to find the task
        const query = { 
            _id: taskId, 
            userId: new ObjectId(req.user.id) 
        };
        console.log("Query to find task:", JSON.stringify(query));
        
        // Check if the task exists before update
        const taskExists = await db.collection("timeAitasks").findOne(query);
        
        console.log("Task exists check result:", taskExists);
        
        if (!taskExists) {
            return res.status(404).json({ error: "Task not found" });
        }
        
        // Prepare update document with only the fields that are provided
        const updateFields = {};
        if (title !== undefined) updateFields.title = title;
        if (startTime !== undefined) updateFields.startTime = startTime;
        if (endTime !== undefined) updateFields.endTime = endTime;
        if (category !== undefined) updateFields.category = category;
        if (priority !== undefined) updateFields.priority = priority;
        
        console.log("Fields to update:", updateFields);
        
        // Proceed with update if task exists
        const result = await db.collection("timeAitasks").findOneAndUpdate(
            query,
            { $set: updateFields },
            { returnDocument: 'after' }  // For MongoDB driver 4.x
        );
        
        console.log("Update result:", result);
        
        // Handle different response formats based on driver version
        const updatedTask = result.value || result;
        
        if (updatedTask) {
            return res.json({ message: "Task updated", task: updatedTask });
        }
        
        // If no task was updated
        return res.status(404).json({ error: "Task not found or not updated" });
    } catch (error) {
        console.error("Error updating task:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
});



// --- Delete Task ---
app.delete("/timeAi/task/:_id", timeAiAuthMiddleware, async (req, res) => {
    const { _id } = req.params;
    
    // Validate ObjectId format
    if (!ObjectId.isValid(_id)) {
        return res.status(400).json({ error: "Invalid task ID" });
    }
    
    const taskId = new ObjectId(_id);
    
    try {
        // Log the query we're using to find and delete the task
        const query = { 
            _id: taskId, 
            userId: new ObjectId(req.user.id) 
        };
        console.log("Query to delete task:", JSON.stringify(query));
        
        // Check if the task exists before deletion
        const taskExists = await db.collection("timeAitasks").findOne(query);
        
        console.log("Task exists check result:", taskExists);
        
        if (!taskExists) {
            return res.status(404).json({ error: "Task not found" });
        }
        
        // Proceed with task deletion
        const result = await db.collection("timeAitasks").findOneAndDelete(query);
        
        console.log("Delete result:", result);
        return res.json({ message: "Deleted sucessfully" });
        
    
        
    } catch (error) {
        console.error("Error deleting task:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
});



// --- Analyze Tasks ---
app.get("/timeAi/analyze", timeAiAuthMiddleware, async (req, res) => {
    const tasks = await db.collection("timeAitasks").find({ userId: new ObjectId(req.user.id) }).toArray();
    if (!Array.isArray(tasks) || tasks.length === 0) {
        return res.status(400).json({ error: "No tasks found to analyze" });
    }

    try {
        const analysisResults = analyzeTasks(tasks);
        res.json(analysisResults);
    } catch (err) {
        console.error("Error analyzing tasks:", err);
        res.status(500).json({ error: "Failed to analyze tasks" });
    }
});


app.get("/timeAi/recommend", timeAiAuthMiddleware, async (req, res) => {
    const tasks = await db.collection("timeAitasks").find({ userId: new ObjectId(req.user.id) }).toArray();
    const recommendation = await getTaskRecommendation(tasks);

    if (recommendation) {
        res.json({ recommendation });
    } else {
        res.status(500).json({ error: "Failed to get recommendation" });
    }
});

// --- Mark Task as Completed ---
// app.put("/timeAi/task/:id/complete", timeAiAuthMiddleware, async (req, res) => {
//     const { id } = req.params;

//     // Validate ObjectId format
//     if (!ObjectId.isValid(id)) {
//         return res.status(400).json({ error: "Invalid task ID" });
//     }

//     const taskId = new ObjectId(id);

//     try {
//         // Update the task's 'completed' field
//         const updatedTask = await db.collection("timeAitasks").findOneAndUpdate(
//             { _id: taskId, userId: new ObjectId(req.user.id) },
//             { $set: { completed: true } },
//             { returnDocument: "after" } // To return the document after it is updated
//         );

//         // Check if the task was found and updated
//         if (!updatedTask.value) {
//             return res.status(404).json({ error: "Task not found or already marked as completed" });
//         }

//         // Debugging log to verify the result of the update
//         console.log('Updated Task:', updatedTask.value);

//         res.json({ message: "Task marked as completed", task: updatedTask.value });
//     } catch (error) {
//         console.error("Error marking task as completed:", error);
//         res.status(500).json({ error: "Internal server error" });
//     }
// });

// app.put("/timeAi/complete/:id", timeAiAuthMiddleware, async (req, res) => {
//     const { id } = req.params;
//     const { completed } = req.body;
  
//     // Validate 'completed' status
//     if (typeof completed !== "boolean") {
//       return res.status(400).json({ message: "Invalid 'completed' status" });
//     }
  
//     try {
//       // Convert id to ObjectId
//       const objectId = new ObjectId(id);
  
//       // Find and update the task
//       const updatedTask = await db.collection("timeAitasks").findOneAndUpdate(
//         { _id: objectId },
//         { $set: { completed } },
//         { returnDocument: "after" } // return the updated document
//       );
  
    
  
//       // Check if the task is already in desired state (before update)
//       if (updatedTask.value.completed === true) {
//         return res.status(400).json({ message: "Task is already in the desired state" });
//       }
  
//       return res.status(200).json({ message: "Task updated successfully", task: updatedTask.value });
//     } catch (error) {
//       return res.status(500).json({ message: "Error updating task", error: error.message });
//     }
//   });
  
  
app.put("/timeAi/complete/:id", timeAiAuthMiddleware, async (req, res) => {
    const { id } = req.params;
    const { completed } = req.body;
  
    // Validate 'completed' status to be a boolean
    if (typeof completed !== "boolean") {
      return res.status(400).json({ message: "Invalid 'completed' status" });
    }
  
    try {
      // Convert the task ID to an ObjectId
      const objectId = new ObjectId(id);
  
      // Fetch the existing task to check the current completion status
      const existingTask = await db.collection("timeAitasks").findOne({ _id: objectId });
  
      // If the task does not exist
      if (!existingTask) {
        return res.status(404).json({ message: "Task not found" });
      }
  
      // Check if the task is already in the desired state (completed or not)
      if (existingTask.completed === completed) {
        return res.status(400).json({
          message: `Task is already marked as ${completed ? "completed" : "incomplete"}`,
        });
      }
  
      // Update the task completion status
      const updatedTask = await db.collection("timeAitasks").findOneAndUpdate(
        { _id: objectId },
        { $set: { completed } },
        { returnDocument: "after" } // Return the updated document
      );
  
      // Return the updated task data
      return res.status(200).json({
        message: "Task updated successfully",
        task: updatedTask.value,
      });
    } catch (error) {
      return res.status(500).json({ message: "Error updating task", error: error.message });
    }
  });

// --- Export Task Data (CSV) ---
app.get("/timeAi/export", timeAiAuthMiddleware, async (req, res) => {
    const tasks = await db.collection("timeAitasks").find({ userId: new ObjectId(req.user.id) }).toArray();
    const csv = json2csv(tasks);
    res.header('Content-Type', 'text/csv');
    res.attachment('tasks.csv');
    res.send(csv);
});

app.get("/timeAi/focus", timeAiAuthMiddleware, async (req, res) => {
    try {
        const tasks = await db.collection("timeAitasks").find({ userId: new ObjectId(req.user.id) }).toArray();
        
        if (!tasks || tasks.length === 0) {
            return res.status(400).json({ error: "No tasks found" });
        }

        // Sort tasks by deadline and priority
        const sortedTasks = tasks.sort((a, b) => {
            if (a.deadline !== b.deadline) {
                return new Date(a.deadline) - new Date(b.deadline); // First by deadline
            }
            return b.priority - a.priority; // Then by priority
        });

        const focusTask = sortedTasks[0];  // Select the first task

        res.json({ message: "Today's focus task", task: focusTask });
    } catch (err) {
        console.error("Error fetching focus task:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.get("/timeAi/weekly-summary", timeAiAuthMiddleware, async (req, res) => {
    try {
        const startOfWeek = new Date();
        startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay()); // Get Sunday of the current week
        startOfWeek.setHours(0, 0, 0, 0);  // Start at midnight
        
        const tasks = await db.collection("timeAitasks")
            .find({ userId: new ObjectId(req.user.id), startTime: { $gte: startOfWeek } })
            .toArray();
        
        const completedTasks = tasks.filter(task => task.completed);
        
        const productivitySummary = {
            createdThisWeek: tasks.length,
            completedThisWeek: completedTasks.length,
            avgTimePerTask: completedTasks.reduce((sum, task) => sum + (new Date(task.endTime) - new Date(task.startTime)), 0) / completedTasks.length || 0,
            mostCommonCategory: findMostCommonCategory(tasks),
        };

        res.json(productivitySummary);
    } catch (err) {
        console.error("Error fetching weekly summary:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/timeAi/productivity-score", timeAiAuthMiddleware, async (req, res) => {
    try {
        const tasks = await db.collection("timeAitasks").find({ userId: new ObjectId(req.user.id) }).toArray();

        if (!tasks || tasks.length === 0) {
            return res.status(400).json({ error: "No tasks found" });
        }

        const totalTasks = tasks.length;
        const completedTasks = tasks.filter(task => task.completed).length;

        // Calculate productivity score (percentage of completed tasks)
        const score = (completedTasks / totalTasks) * 100;

        const productivityTips = score < 50 ? "Try to complete more tasks to improve your productivity!" : "You're doing great, keep it up!";

        res.json({
            productivityScore: score.toFixed(2),
            tips: productivityTips,
        });
    } catch (err) {
        console.error("Error calculating productivity score:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/timeAi/task/category-predict", timeAiAuthMiddleware, async (req, res) => {
    const { title } = req.body;
    const categoryKeywords = {
        Work: ['meeting', 'project', 'work', 'deadline'],
        Health: ['exercise', 'gym', 'workout', 'health'],
        Personal: ['shopping', 'friends', 'family', 'leisure'],
    };

    let predictedCategory = "Uncategorized";  // Default category
    
    // Check keywords in title to predict category
    for (let [category, keywords] of Object.entries(categoryKeywords)) {
        for (let keyword of keywords) {
            if (title.toLowerCase().includes(keyword)) {
                predictedCategory = category;
                break;
            }
        }
    }

    res.json({ predictedCategory });
});






app.listen(3000, () => {
    console.log("Server running on port 3000");
});
