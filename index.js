
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const shortid = require("shortid");
const cors = require("cors");
const bcrypt = require("bcrypt");

// Set up Express
const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URL, {
  })
  .then(() => console.log("Connected to db"))
  .catch((err) => console.log(err));

// Create URL schema with additional fields for click counts and visitor details
const urlSchema = new mongoose.Schema(
  {
    shortId: String,
    originalUrl: String,
    totalClicks: { type: Number, default: 0 }, // Total clicks
    uniqueClicks: { type: Number, default: 0 }, // Unique visitor clicks
    visitorDetails: [
      // Array to store visitor details
      {
        visitorId: String,
        city: String,
      },
    ],
  },
  {
    timestamps: true, // Automatically adds `createdAt` and `updatedAt` fields
  }
);

const Url = mongoose.model("Url", urlSchema);

app.get("/heath", async (req, res) => {
  res.send("Server is running");
});

// Route to get all info
app.get("/get-info", async (req, res) => {
  try{
    const urlData = await Url.find({});
    if(urlData){
      res.json({
        success : true,
        urlData
      })
    }
    else res.json({success:false})
  }
  catch(e){
    res.status(404).json({message : "Error occured : No data found"})
  }
  
});



// Route to verify a hashed word
app.get("/compare/:word/:hash", async (req, res) => {
  const { word, hash } = req.params;
  try {
    const isMatch = await bcrypt.compare(word, hash);
    res.json({ success : isMatch });
  } catch (error) {
    res.status(500).json({ error: "Error comparing the word" });
  }
}
);


// Route to create a short URL
app.post("/shorten", async (req, res) => {
  const { originalUrl } = req.body;
  const shortId = shortid.generate();

  // Save the original URL and its shortId to the database
  const newUrl = new Url({ shortId, originalUrl });
  await newUrl.save();

  res.json({
    shortUrl: `https://pickand-partner-ten.vercel.app/${shortId}`,
  });
});

// Route to handle redirection
app.get("/:shortId", async (req, res) => {
  const { shortId } = req.params;
  const urlRecord = await Url.findOne({ shortId });

  if (urlRecord) {
    // Include originalUrl in the redirect to frontend
    const redirectUrl = `https://finger-print-clicks.vercel.app/?shortId=${shortId}&originalUrl=${encodeURIComponent(urlRecord.originalUrl)}`;
    res.redirect(redirectUrl);
  } else {
    res.status(404).json({ message: "URL not found" });
  }
});

// Route to store visitor ID and city information
app.post("/store-visitor-id", async (req, res) => {
  const { visitorId, shortId, city } = req.body;
  const urlRecord = await Url.findOne({ shortId });
  if (urlRecord) {
    urlRecord.totalClicks += 1;
    const isUniqueVisitor = !urlRecord.visitorDetails.some(visitor => visitor.visitorId === visitorId);
    if (isUniqueVisitor) {
      urlRecord.uniqueClicks += 1;
      urlRecord.visitorDetails.push({ visitorId, city });
    }
    await urlRecord.save();
    res.json({ success: true });
  } else {
    res.status(404).json({ message: "URL not found" });
  }
});



// Start the server
const PORT = 3004;
app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});