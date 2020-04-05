const Sequelize = require('sequelize');

const sequelizeConnection = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: 'mysql',
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  }
);

sequelizeConnection
  .authenticate()
  .then(() => console.log('Database successfully connected'))
  .catch(err => console.log('Database Failed to connect Error: ', +err));

module.exports.sequelizeConnection = sequelizeConnection;
