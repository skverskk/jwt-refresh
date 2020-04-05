'use strict';
module.exports = (sequelize, DataTypes) => {
  const Token = sequelize.define(
    'Token',
    {
      user_id: DataTypes.STRING,
      refresh_token: DataTypes.TEXT,
      create_date: DataTypes.DATE,
      revoke_date: DataTypes.DATE
    },
    {}
  );
  Token.associate = function(models) {
    // associations can be defined here
  };
  return Token;
};
