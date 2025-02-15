const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion } = require("mongodb");

//middleware:
const corsOptions = {
  origin: ["http://localhost:5173"],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.s1tjtzs.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

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
    const usersCollection = client.db("Ekash").collection("users");
    const transactionsCollection = client
      .db("Ekash")
      .collection("transactions");
    const requestsCollection = client.db("Ekash").collection("requests");
    await client.connect();
    // Send a ping to confirm a successful connection

    //JWT :

    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    //verify:
    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "Forbidden Access" });
      }
      const token = req.headers.authorization.split(" ")[1];
      //console.log(token);
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: "Forbidden Access" });
        }
        req.decoded = decoded;
        //console.log(req.decoded);
        next();
      });
    };

    //verify Admin
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      const isAdmin = user?.role == "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    //Registration

    app.post("/users", async (req, res) => {
      const salt = await bcrypt.genSalt(10);
      const securePin = await bcrypt.hash(req.body.pin, salt);
      const user = req.body;
      const result = await usersCollection.insertOne({
        ...user,
        pin: securePin,
      });
      res.send(result);
    });

    //Login
    app.post("/login", async (req, res) => {
      const email = req.body.email;
      const isExist = await usersCollection.findOne({ email });
      const pin = req.body.pin;
      const pinMatched = await bcrypt.compare(pin.toString(), isExist.pin);
      if (pinMatched) {
        res.send(isExist);
      }
    });

    //Login (number)
    app.post("/login-number", async (req, res) => {
      const number = req.body.number;
      const pin = req.body.pin;
      const isExistNumber = await usersCollection.findOne({ number });
      const pinMatchedWithNumber = await bcrypt.compare(
        pin.toString(),
        isExistNumber.pin
      );
      if (pinMatchedWithNumber) {
        res.send(isExistNumber);
      }
    });

    //get all users:
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    //get individual user:
    app.get("/users/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const result = await usersCollection.findOne({ email });
      res.send(result);
    });

    //Update user status :
    app.patch(
      "/users/update/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email;
        const user = req.body;
        const query = { email };
        const updatedDoc = {
          $set: {
            ...user,
          },
        };
        const result = await usersCollection.updateOne(query, updatedDoc);
        res.send(result);
      }
    );

    //send money:
    app.patch("/users/sendMoney/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const updatedBalance = req.body.amount;

      //finding the user to send
      const sendUserNumber = req.body.sentTo;
      const receiverUser = await usersCollection.findOne({
        number: sendUserNumber,
        role: "user",
      });

      ///checking pin is okay or not
      const pin = req.body.pin;
      const user = await usersCollection.findOne({ email });
      const pinMatchedWithNumber = await bcrypt.compare(
        pin.toString(),
        user.pin
      );

      const newBalance = parseFloat(user.balance) - parseFloat(updatedBalance);
      const newReceiverBalance =
        parseFloat(receiverUser.balance) + parseFloat(updatedBalance);
      try {
        if (receiverUser && pinMatchedWithNumber) {
          //  const query = { email };
          const updatedDoc = {
            $set: {
              balance: newBalance,
            },
          };
          const updatedReceiverBalance = {
            $set: {
              balance: newReceiverBalance,
            },
          };
          const update = await usersCollection.updateOne(user, updatedDoc);
          const update1 = await usersCollection.updateOne(
            receiverUser,
            updatedReceiverBalance
          );
          res.status(200).send({
            message: "Transaction successful",
            senderUpdate: update,
            receiverUpdate: update1,
          });
        } else {
          res.status(401).send({ error: "Enter a valid User Number" });
        }
      } catch (err) {
        res.status(401).send({ error: "something is wrong" });
      }
    });

    //add new transaction :
    app.post("/transactions", verifyToken, async (req, res) => {
      const transaction = req.body;
      const result = await transactionsCollection.insertOne(transaction);
      res.send(result);
    });

    //individual transactions:
    app.get("/transaction/:email",verifyToken,async(req,res)=>{
      const email=req.params.email;
      const result=await transactionsCollection.find({UserEmail:email}).toArray()
      res.send(result)
    })

    //cash in :
    app.post("/cash-in", verifyToken,async (req, res) => {
      //finding the user to send
      const agentNumber = req.body.sentTo;
      const agent = await usersCollection.findOne({
        number: agentNumber,
        role: "agent",
      });
      console.log("Agent is ", agent);

       ///checking pin is okay or not
       const email = req.body.UserEmail;
       const pin = req.body.pin;
       const user = await usersCollection.findOne({ email });
       const pinMatchedWithNumber = await bcrypt.compare(
         pin.toString(),
         user.pin
       );
       try {
        if (pinMatchedWithNumber && agent) {
          const salt = await bcrypt.genSalt(10);
          const securePin = await bcrypt.hash(req.body.pin, salt);
          const user = req.body;
          const result = await requestsCollection.insertOne({
            ...user,
            pin: securePin,
          });
          res.send(result);
        }else{
          res.status(401).send({ error: "Enter a valid  Number" });
        }
      } catch (err) {
        res.status(401).send({ error: "something is wrong" });
      }
    });



    //cash out:
    app.post("/cash-out", verifyToken,async (req, res) => {
      //finding the user to send
      const agentNumber = req.body.sentTo;
      const agent = await usersCollection.findOne({
        number: agentNumber,
        role: "agent",
      });
      console.log("Agent is ", agent);

      ///checking pin is okay or not
      const email = req.body.UserEmail;
      const pin = req.body.pin;
      const user = await usersCollection.findOne({ email });
      const pinMatchedWithNumber = await bcrypt.compare(
        pin.toString(),
        user.pin
      );

      try {
        if (pinMatchedWithNumber && agent) {
          const salt = await bcrypt.genSalt(10);
          const securePin = await bcrypt.hash(req.body.pin, salt);
          const user = req.body;
          const result = await requestsCollection.insertOne({
            ...user,
            pin: securePin,
          });
          res.send(result);
        }else{
          res.status(401).send({ error: "Enter a valid  Number" });
        }
      } catch (err) {
        res.status(401).send({ error: "something is wrong" });
      }
    });


    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Ekash is running successfully");
});

app.listen(port, () => {
  console.log(`Ekash is running on ${port}`);
});
