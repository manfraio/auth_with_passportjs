const Datastore = require('nedb-promises')

const users = Datastore.create('./users.db')

module.exports = { users }