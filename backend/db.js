const { MongoClient } = require('mongodb');
require('dotenv').config();
let dbConnection;
let url=process.env.MONGODB_URL
module.exports = {
    connectToDb: (cb) => { // corrected from connectTodb to connectToDb
        MongoClient.connect(url)
            .then((client) => {
                dbConnection = client.db();
                console.log("database connected")
                return cb();
            })
            .catch(err => {
                console.log(err);
                return cb(err);
            });
    },
    getDb: () => dbConnection
};