const express = require('express')

//we want to bring in speak easy library 
const speakeasy = require('speakeasy')

//we want to bring in uuid, we're going to user that to generate a user id because node json db doesn't do that it's own 
const uuid = require('uuid')
const { JsonDB } = require('node-json-db')
const { Config } = require('node-json-db/dist/lib/JsonDBConfig')


const app = express()

app.use(express.json())

// Initializing a an instance of json DB which takes in a config instance and then xouple of arguments first will be the name of the database, we'll call it my database and then second is we're going to say true which related to when we do a push so when we do db.push we want it to save if we don't put "true" here if we have false then it's going to we're going to have add another save method in addition to push, false this has to do with having it be human readable and then the separator is going to be a slash "/" which I believe is the defaul
const db = new JsonDB(new Config('myDatabase', true, false, '/'))

app.get('/api', (request, response) => response.json({ message: 'Welcome to the two factor authentication example'}))


// so the way it's going to work is we register a user it's just going to be an id and the temp secret and once the user is registered we'll create another route to verify where we can then use the authenticator to get token and we can then verify that token against the temporary secret in the database and if it validates or if it verfies then we're going to change it from temo secret to just secret and then we'll have a final route where we can just validate with any token from the authenticator.

app.post('/api/register', (request, response) => {
    const id = uuid.v4()

    try{
        //we're going to create a temp secret
        const path = `/user/${id}`
        //we're going to create a temp secret
        const temp_secret = speakeasy.generateSecret()
        //we're going to push that temp secret to the database
        db.push(path, { id, temp_secret})
        //we're going to send back to the user the id and the base 32 encoded secret
        response.json({ id, secret: temp_secret.base32})
    } 
    catch (error){
        console.log(error)
        response.status(500).json({ message: 'Error generating secret key'})
    }
})

// Verify token and make secret perm
app.post('/api/verify', (request, response)=>{

    const { token, userId } = request.body
    try{
        // Retrieve user from database
        const path = `/user/${userId}`
        const user = db.getData(path)

        // Verify token
        const { base32: secret } = user.temp_secret

        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token
        })

        if(verified){
            db.push(path, { id: userId, secret: user.temp_secret})
            response.json({ verified: true})
        } else {
            response.json({ verified: false})
        }
    } catch (error){
        console.log(error)
        response.status(500).json({ message: 'Error retrieving user'})
    }
})

app.post("/api/validate", (req,res) => {
    const { userId, token } = req.body;
    try {
      // Retrieve user from database
      const path = `/user/${userId}`;
      const user = db.getData(path);
      console.log({ user })
      const { base32: secret } = user.secret;
      // Returns true if the token matches
      const tokenValidates = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 1
      });
      if (tokenValidates) {
        res.json({ validated: true })
      } else {
        res.json({ validated: false})
      }
    } catch(error) {
      console.error(error);
      res.status(500).json({ message: 'Error retrieving user'})
    };
  })
  
  const port = 9000;
  
  app.listen(port, () => {
    console.log(`App is running on PORT: ${port}.`);
  });
