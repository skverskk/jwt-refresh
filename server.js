require('dotenv').config();
const express = require('express');
const hbs = require('express-handlebars');
const db = require('./config/db');

const authRoute = require('./routes/auth');
const adminRoute = require('./routes/admin');

app = express();

/** ------------------------------     HANDLEBARS     ------------------------------    */

app.engine('hbs', hbs({ extname: 'hbs', defaultLayout: 'main' }));
app.set('view engine', 'hbs');

// MySql Server Setup
db.sequelizeConnection;

/** ------------------------------     BODY PARSE    ------------------------------    */

app.use(express.json()); // for parsing application/json
app.use(express.urlencoded({ extended: false }));
// Prettify json output
app.set('json spaces', 4);

/** ------------------------------     ROUTES    ------------------------------    */

app.use('/api/auth', authRoute);
app.use('/api/admin', adminRoute);

app.get('/', (req, res) => {
  res.send('ROOT');
});
/** ------------------------------     SERVER    ------------------------------    */

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server runnin at localhost:${PORT}`);
});
