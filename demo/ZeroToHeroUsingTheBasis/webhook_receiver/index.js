const express = require('express')
const app = express()
const port = 3000

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get('/', (req, res) => {
  console.log("---------------------------")
  console.log("GET ROOT /")
  console.log("---------------------------")
  console.log(req.rawHeaders)
  res.send('Hello World!')
})

app.get('/webhooks/*', (req, res) => {
  console.log("---------------------------")
  console.log("GET WEBHOOKS /webhooks")
  console.log("---------------------------")
  console.log(req.rawHeaders)
  res.send('ok!')
})

app.post('/webhooks/*', (req, res) => {
  console.log("---------------------------")
  console.log("POST WEBHOOKS /webhooks")
  console.log("---------------------------")
  console.log(req.rawHeaders)
  if(req.body.credential_exchange_id) {
    delete req.body.credential_offer
    delete req.body.credential_request
    delete req.body.credential_proposal_dict
    delete req.body.credential
    delete req.body.credential_offer_dict
    console.log(req.body)
  } else {
    console.log(req.body)
  }
  res.send('ok!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
