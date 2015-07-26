var express = require('express')
var app = express()
var logger = require('morgan')
var Datastore = require('nedb')
var db = new Datastore({ filename: 'collector.db', autoload: true})



app.set('views', __dirname + '/views')
app.set('view engine', 'jade')


app.use(logger('dev'))

app.get('/', function (req, res, next) {
	db.find({}, {cid:1}, function (err, docs) {
		res.render('users', {docs: docs})
	})
})

app.get('/detail/:cid', function (req, res, next) {
	db.findOne({cid: req.params.cid}, function (err, doc) {
		res.render('details', {doc: doc, cid: req.params.cid})
	})
})

app.listen(8090)
console.log('Started at 8090')