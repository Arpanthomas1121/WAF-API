//Import the required modules
const http = require('http');
const https = require('https');
const helmet = require('helmet');
const express = require('express');
const sql = require('mysql2');
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');
const httpProxy = require('http-proxy');
const { createProxyMiddleware } = require('http-proxy-middleware');
const moment = require ('moment');
const port = process.env.PORT || 3002;
const IP = require('ip');

// // Define the path to the logs directory
// const logDirectory = path.join(__dirname, 'logs');

// // Check if the logs directory exists
// // If it doesn't, create it
// if (!fs.existsSync(logDirectory)) {
//   fs.mkdirSync(logDirectory);
// }

// // Create a write stream for the access log file
// const accessLogStream = fs.createWriteStream(
//   path.join(logDirectory, 'access.log'),
//   {flags: 'a'}
// );

// Create an instance of the express application
const app = express();

// // Use the morgan middleware to log HTTP requests
// app.use(
//   morgan('combined', {
//     stream: accessLogStream
//   })
// );

// Define a global object to hold banned IPs and their ban timestamps
const bannedIPs = {};
const requestCounts = {};

// Function to ban an IP for 10 minutes
function ban_ip(ip) {
  bannedIPs[ip] = Date.now() + 10 * 60 * 1000;
}

// Function to check if an IP is banned
function is_ip_banned(ip) {
  const banTime = bannedIPs[ip];
  return banTime && banTime > Date.now();
}

// Middleware function to rate limit requests
const limiter = (req, res, next) => {
  const rateLimit = 10; // Maximum requests per IP in a given time frame
  const ip = req.socket.remoteAddress;// Check if request has an array of IP addresses
//const ip = IP.address();
//Check if the IP is banned
  if (is_ip_banned(ip)) {
    console.log(`IP ${ip} is banned`);
    res.statusCode = 429; // Return error with status code 429 (Too Many Requests) if IP is banned
    return res.end(`Too many requests from IP ${ip}`);
  }

  // Increment the request count for the IP
  if (!requestCounts[ip]) {
    requestCounts[ip] = 1;
  } else {
    requestCounts[ip] += 1;
  }

  // Ban the IP if request count exceeds rate limit
  if (requestCounts[ip] > rateLimit) {
    console.log(`IP ${ip} exceeded the rate limit`);
    ban_ip(ip);
    res.statusCode = 429; // Return error with status code 429 (Too Many Requests) if IP exceeds rate limit
    return res.end(`Too many requests from IP ${ip}`);
  }

  // Call next middleware if IP is not banned and request count is within the rate limit
  next();
};

// Export the bannedIPs object so it can be used by other parts of the application
module.exports.bannedIPs = bannedIPs;

// Apply the rate-limiting middleware
app.use(limiter);


// Custom middleware to prevent directory traversal attacks
const publicDirectories = [ "/public", "/greeting", "/big", "/home", "/login"];
var request;
app.use((req, res, next) => {
// Normalize the requested path to prevent encoding attacks
const path = decodeURIComponent(req.path).split('.')[0];
console.log('path: ',path);
  request=path;
// Check if the requested path is in the list of public directories
if (publicDirectories.some(publicDirectories => path.startsWith(publicDirectories))) {
  // If it is, continue to the next middleware
  next();
} else {
// If not, return a 401 Unauthorized status
console.log('Unauthorized access attempt: ', req.method, req.originalUrl);
res.status(401).send("401 Unauthorized");
}
});

// Apply the helmet middleware to add various security-related HTTP headers
app.use((req, res, next) => {
  helmet()(req, res, () => {
    console.log(`Helmet middleware ran for request with URL: ${req.url}`);
    next();
  });
});

// Define the database connection properties
const dbProperties = {
  connectionLimit: 10,  // Maximum number of connections to create in the pool
  host: process.env.DB_HOST,  // Hostname of the database server
  user: process.env.DB_USER,  // Database username
  password: process.env.DB_PASSWORD,  // Database password
  database: process.env.DB_NAME  // Name of the database to connect to
};

// Create a connection pool for the database using the defined properties
const pool = sql.createPool(dbProperties);

//Import the Sequelize library
const Sequelize = require('sequelize');

// Create a new Sequelize instance, connecting to a MySQL database
const sequelize = new Sequelize('database', 'username', 'password', {
host: 'localhost',
dialect: 'mysql'
});

// Define a model for a user in the database
const User = sequelize.define('user', {
username: Sequelize.STRING,
password: Sequelize.STRING
});

// Add a custom middleware to prevent SQL injections
app.use((req, res, next) => {
  // Check if username and password queries exist in req.query
  if (req.query.username && req.query.password) {
    // Use Sequelize to automatically escape any potentially dangerous input
    User.findOne({
      where: {
        username: Sequelize.escape(req.query.username),
        password: Sequelize.escape(req.query.password)
      }
    })
      .then(user => {
        // If the user was found in the database, call the next middleware
        if (user) {
          next();
        } else {
          // If the user was not found, return a 400 Bad Request response
          res.status(400).send('Bad Request');
        }
      })
      .catch(error => {
        // If there was an error in the query, return a 500 Internal Server Error response
        res.status(500).send(error.message);
      });
  } else {
    // If username and password queries don't exist, call the next middleware
    next();
  }
});


// Custom middleware to sanitize query parameters
app.use((req, res, next) => {
const { query } = req;
const parameters = Object.keys(query);
const parametrizedQuery = {};
parameters.forEach(parameter => {
// Escaping potentially dangerous characters in the query values using encodeURIComponent
parametrizedQuery[parameter] = encodeURIComponent(query[parameter]);
});
req.parametrizedQuery = parametrizedQuery;
console.log('Sanitized query parameters:', req.parametrizedQuery);
next();
});

app.use((req,res)=>{
    res.redirect('https://cyberv-webserver.onrender.com'+ request);
    // res.redirect('http://localhost:3002'+ req.url);
//  res.status(200).send("OK");
});

// uncomment this when running in local host 
// const server = app.listen(3001, 'localhost', () => {
//   console.log("WAF listening on port 3001");
// });
app.listen(port, () => console.log(`WAF server listening on port ${port}!`));
