require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { connectToDb, getDb } = require("./db");
const { ObjectId } = require("mongodb");

const app = express();
app.use(cors());
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
// Task analysis function
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

// --- Signup ---
app.post("/timeAi/signup", async (req, res) => {
    const { name, email, password } = req.body;
    const existing = await db.collection("timeAiuser").findOne({ email });
    if (existing) return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const result = await db.collection("timeAiuser").insertOne({ name, email, password: hashed });

    const token = jwt.sign({ id: result.insertedId, email }, process.env.JWT_SECRET);
    console.log("JWT Token after signup:", token); // ✅ For testing in console

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

    // Send token as response and store it for future use
    res.json({ message: "Login successful", token });
});

// --- Add Task ---
app.post("/timeAi/task", timeAiAuthMiddleware, async (req, res) => {
    const { title, startTime, endTime, category } = req.body;
    const task = {
        userId: new ObjectId(req.user.id),
        title,
        startTime,
        endTime,
        category,
    };
    await db.collection("timeAitasks").insertOne(task); // Updated task collection name
    res.json({ message: "Task added" });
});

// --- Get Tasks ---
app.get("/timeAi/tasks", timeAiAuthMiddleware, async (req, res) => {
    const tasks = await db.collection("timeAitasks").find({ userId: new ObjectId(req.user.id) }).toArray(); // Updated task collection name
    res.json(tasks);
});

// --- Analyze Tasks ---

app.get("/timeAi/analyze", timeAiAuthMiddleware, async (req, res) => {
    // Fetch the tasks for the authenticated user
    const tasks = await db.collection("timeAitasks").find({ userId: new ObjectId(req.user.id) }).toArray();

    // Log the received tasks for debugging
    console.log("Received tasks:", tasks);

    // Validate if tasks is an array and has a length
    if (!Array.isArray(tasks) || tasks.length === 0) {
        return res.status(400).json({ error: "No tasks found to analyze" });
    }

    try {
        // Proceed with the analysis logic
        const analysisResults = analyzeTasks(tasks);
        res.json(analysisResults);  // Send analysis result to the client
    } catch (err) {
        console.error("Error analyzing tasks:", err);
        res.status(500).json({ error: "Failed to analyze tasks" });
    }
});


// --- Start Server ---
app.listen(3001, () => console.log("Server running on http://localhost:3001"));
