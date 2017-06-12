const low = require('lowdb');
const db = low('db-test.json');
db.defaults({ posts: [] }).write();
console.log(db.get('posts').value())
    /*db.get('posts')
      .push({ id: 1, title: 'lowdb is awesome1'})
      .write()
      db.get('posts')
      .push({ id: 2, title: 'lowdb is awesome2'})
      .write()
      db.get('posts')
      .push({ id: 3, title: 'lowdb is awesome3'})
      .write()
      db.get('posts')
      .push({ id: 4, title: 'lowdb is awesome4'})
      .write()*/
