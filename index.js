const express = require("express");
const app = express();
const cors = require("cors");
require("dotenv").config();
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const mg = require("nodemailer-mailgun-transport");
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

const auth = {
  auth: {
    api_key: process.env.EMAIL_PRIVATE_KEY,
    domain: process.env.EMAIL_DOMAIN,
  },
};

const transporter = nodemailer.createTransport(mg(auth));

const sendTokenEmail = (email, token) => {
  transporter.sendMail({
    from: "robin.shrkr@gmail.com",
    to: email,
    subject: "Password Reset Request",
    text: `
      Hi,

      You have requested to reset your password. Here is Your Token:

                   ${token}

      If you did not request to reset your password, please ignore this email.
    `,
  });
};

app.get("/", (req, res) => {
  res.send("Auth Running");
});

const { MongoClient, ServerApiVersion } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.bioniru.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();

    const usersCollection = client.db("authDB").collection("users");
    const tokenCollection = client.db("authDB").collection("token");

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );

    app.post("/register", async (req, res) => {
      const { name, email, password } = req.body;

      const existingUser = await usersCollection.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "Email already registered" });
      }

      await usersCollection.insertOne({
        name,
        email,
        password,
      });

      res.status(200).send({ message: "Registration successful" });
    });

    // app.get("/users", async (req, res) => {
    //   const result = await usersCollection.find().toArray();
    //   res.send(result);
    // });

    app.post("/login", async (req, res) => {
      const { email, password } = req.body;
      const user = await usersCollection.findOne({ email });
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }
      if (user.password !== password) {
        return res.status(401).send({ message: "Invalid password" });
      }

      res.status(200).send({ message: "Login successful" });
    });

    app.post("/reset", async (req, res) => {
      const { email } = req.body;
      console.log(email);

      const resetToken = Math.ceil(Math.random() * 100000);

      await tokenCollection.insertOne({
        email,
        token: resetToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      });
      sendTokenEmail(email, resetToken);

      res.status(200).send({ message: "Password reset email sent" });
    });

    app.post("/reset-password", async (req, res) => {
      const { email, token, newPassword } = req.body;
      const resetToken = await tokenCollection.findOne({ email });
      console.log(resetToken);
      if (!resetToken || resetToken.expiresAt < new Date()) {
        return res.status(400).send({ message: "Invalid or expired token" });
      }

      await usersCollection.updateOne(
        { email },
        { $set: { password: newPassword } }
      );

      await tokenCollection.deleteOne({ _id: resetToken._id });

      res.status(200).send({ message: "Password reset successful" });
    });
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(port, (req, res) => {
  console.log(`Auth running on Port: ${port}`);
});
