const sanitizeUser = (user) => {
    const { password, ...sanitizedUser } = user.toObject ? user.toObject() : user;
    return sanitizedUser;
  };
  
  module.exports = sanitizeUser;