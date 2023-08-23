const express = require("express");
const app = express();
const cors = require("cors");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const mg = require("nodemailer-mailgun-transport");
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

const secretKey = process.env.SECRET_KEY;
const iv = crypto.randomBytes(16);

const verifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "Unauthorized access" });
  }
  const token = authorization.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .send({ error: true, message: "Unauthorized access" });
    }
    req.decoded = decoded;
    next();
  });
};

const encryptEmail = (email, secretKey, iv) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
  let encryptedEmail = cipher.update(email, 'utf8', 'hex');
  encryptedEmail += cipher.final('hex');
  return encryptedEmail;
};

const decryptEmail = (encryptedEmail, secretKey, iv) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
  let decryptedEmail = decipher.update(encryptedEmail, 'hex', 'utf8');
  decryptedEmail += decipher.final('utf8');
  return decryptedEmail;
};


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

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
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
    const postCollection = client.db("authDB").collection("posts");

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
      const encryptedPass = await bcrypt.hash(password, 10);
      const encryptedEmail = encryptEmail(email, secretKey, iv);
      await usersCollection.insertOne({
        name,
        email: encryptedEmail,
        password: encryptedPass,
      });

      res.status(200).send({ message: "Registration successful" });
    });

    app.get("/users", verifyJWT, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    app.post("/login", verifyJWT, async (req, res) => {
      const { email, password } = req.body;
      const user = await usersCollection.findOne({ email });
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }
      const decryptedEmail = decryptEmail(user.email, secretKey, iv);
   if (email !== decryptedEmail) {
     return res.status(401).send({ message: "Invalid email" });
   }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
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
// get all the post
    app.get("/posts", verifyJWT, async (req, res) => {
      const result = await postCollection.find().toArray();
      res.send(result);
    });
    // add post
    app.post("/posts", verifyJWT, async (req, res) => {
      const post = req.body;
      await postCollection.insertOne(post);
      res.status(200).send({ message: "Added Post successfully" });
    });
    // edit post
    app.put("/posts/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const updatedDoc = req.body;
      const query = { _id: new ObjectId(id) };
      const update = {
        $set: updatedDoc,
      };
      await postCollection.updateOne(query, update);
      res.status(200).send({ message: "Edited Post successfully" });
    });
    // like post
    app.post("/likes/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const post = await postCollection.findOne(query);
      const isLiked = post.likes > 0;
      const updated = isLiked
        ? { $inc: { likes: -1 } }
        : { $inc: { likes: 1 } };
       await postCollection.updateOne(query, updated);
      res.status(200).send({ message: "Increased/Decreased Like successfully" });
    });
// add comment
    app.post("/comments/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const text = req.body;
      const comment = {
        _id: new ObjectId(), 
        text: text,
      };
      const query = { _id: new ObjectId(id) };
      const update = {
        $push: { comments: comment },
      };

       await postCollection.updateOne(query, update);
       res.status(200).send({ message: "Added Comment successfully" });
    });
    // update comment
    app.patch("/comments/:postId/:commentId", verifyJWT, async (req, res) => {
      const postId = req.params.postId;
      const commentId = req.params.commentId;
      const comment = req.body;
      const query = { _id: new ObjectId(postId), "comments._id": new ObjectId(commentId) };
      const update = {
        $set: {"comments.$.text": comment},
      };
      await postCollection.updateOne(query, update);
      res.status(200).send({ message: "Updated Comment successfully" });
    });
    // delete comment
    app.delete("/comments/:postId/:commentId", verifyJWT, async (req, res) => {
      const postId = req.params.postId;
      const commentId = req.params.commentId;
      const query = { _id: new ObjectId(postId) };
      const update = {
        $pull: { comments: { _id: new ObjectId(commentId) } },
      };
      const result = await postCollection.updateOne(query, update);
      res.status(200).send({ message: "Deleted Comment successfully" });
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
