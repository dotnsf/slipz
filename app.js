// app.js

var cfenv = require( 'cfenv' );
var express = require( 'express' );
var bodyParser = require( 'body-parser' );
var crypto = require( 'crypto' );
var fs = require( 'fs' );
var jwt = require( 'jsonwebtoken' );
var os = require( 'os' );
var OAuth = require( 'oauth' );
var request = require( 'request' );
var session = require( 'express-session' );
var app = express();

var settings = require( './settings' );
var appEnv = cfenv.getAppEnv();

app.set( 'superSecret', settings.superSecret );
app.use( express.static( __dirname + '/public' ) );
app.use( bodyParser.urlencoded() );
app.use( bodyParser.json() );

app.use( session({
  secret: settings.superSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,           //. https で使う場合は true
    maxage: 1000 * 60 * 60   //. 60min
  }
}) );

app.set( 'views', __dirname + '/templates' );
app.set( 'view engine', 'ejs' );


//. Twitter API
var oa = new OAuth.OAuth(
  "https://api.twitter.com/oauth/request_token",
  "https://api.twitter.com/oauth/access_token",
  settings.twitter_consumer_key,
  settings.twitter_consumer_secret,
  "1.0A",
  null, //"http://127.0.0.1:3000/twitter/callback",
  "HMAC-SHA1"
);

app.get( '/twitter', function( req, res ){
  oa.getOAuthRequestToken( function( err, oauth_token, oauth_token_secret, results ){
    if( err ){
      console.log( err );
      //res.send( "error(1): " + err );
      res.redirect( '/' );
    }else{
      req.session.oauth = {};
      req.session.oauth.token = oauth_token;
      req.session.oauth.token_secret = oauth_token_secret;
      //console.log( 'oauth_token = ' + oauth_token + ', oauth_token_secret = ' + oauth_token_secret );
      res.redirect( 'https://twitter.com/oauth/authenticate?oauth_token=' + oauth_token );
    }
  });
});

app.get( '/twitter/callback', function( req, res, next ){
  if( req.session.oauth ){
    req.session.oauth.verifier = req.query.oauth_verifier;
    var oauth = req.session.oauth;
    oa.getOAuthAccessToken( oauth.token, oauth.token_secret, oauth.verifier, function( err, oauth_access_token, oauth_access_token_secret, results ){
      if( err ){
        console.log( err );
        //res.send( "error(2): " + err );
        res.redirect( '/' );
      }else{
        //req.session.oauth.access_token = oauth_access_token;
        //req.session.oauth.access_token_secret = oauth_access_token_secret;
        //console.log( results );
        req.session.oauth.provider = 'twitter';
        req.session.oauth.user_id = results.user_id;
        req.session.oauth.screen_name = results.screen_name;

        var token = jwt.sign( req.session.oauth, app.get( 'superSecret' ), { expiresIn: '25h' } );
        req.session.token = token;
        //res.send( "Worked." );
        res.redirect( '/' );
      }
    });
  }else{
    //next( new Error( "you are not supposed to be here." ) );
    res.redirect( '/' );
  }
});


app.get( '/', function( req, res ){
  if( req.session && req.session.token ){
    var token = req.session.token;
    jwt.verify( token, app.get( 'superSecret' ), function( err, user ){
      if( !err && user ){
        res.render( 'index', { user: user, ogp: settings.ogp } );
      }else{
        res.render( 'index', { user: null, ogp: settings.ogp } );
      }
    });
  }else{
    res.render( 'index', { user: null, ogp: settings.ogp } );
  }
});

app.post( '/logout', function( req, res ){
  req.session.token = null;
  //res.redirect( '/' );
  res.write( JSON.stringify( { status: true }, 2, null ) );
  res.end();
});


app.get( '/profileimage', function( req, res ){
  var screen_name = req.query.screen_name;
  if( screen_name ){
    var option = {
      url: 'https://twitter.com/' + screen_name + '/profile_image?size=original',
      method: 'GET'
    };
    request( option, ( err0, res0, body0 ) => {
      if( err0 ){
        return res.status( 403 ).send( { status: false, error: err0 } );
      }else{
        //console.log( res0.headers['content-type'] );
        //console.log( res0.request.path );
        res.redirect( 'https://pbs.twimg.com' + res0.request.path );
      }
    });
  }else{
    return res.status( 403 ).send( { status: false, error: 'No screen_name provided.' } );
  }
});


//. ここより上で定義する API には認証フィルタをかけない
//. ここより下で定義する API には認証フィルタをかける
app.use( function( req, res, next ){
  if( req.session && req.session.token ){
    //. トークンをデコード
    var token = req.session.token;
    if( !token ){
      return res.status( 403 ).send( { status: false, result: 'No token provided.' } );
    }

    jwt.verify( token, app.get( 'superSecret' ), function( err, decoded ){
      if( err ){
        return res.json( { status: false, result: 'Invalid token.' } );
      }

      req.decoded = decoded;
      next();
    });
  }else{
    return res.status( 403 ).send( { status: false, result: 'No token provided.' } );
  }
});


function compareByTimestamp( a, b ){
  var r = 0;
  if( a.timestamp < b.timestamp ){ r = -1; }
  else if( a.timestamp > b.timestamp ){ r = 1; }

  return r;
}

function compareByTimestampRev( a, b ){
  var r = 0;
  if( a.timestamp < b.timestamp ){ r = 1; }
  else if( a.timestamp > b.timestamp ){ r = -1; }

  return r;
}


function generateHash( data ){
  return new Promise( function( resolve, reject ){
    if( data ){
      //. hash 化
      var sha512 = crypto.createHash( 'sha512' );
      sha512.update( data );
      var hash = sha512.digest( 'hex' );
      resolve( hash );
    }else{
      resolve( null );
    }
  });
}

function timestamp2datetime( ts ){
  var dt = new Date( ts );
  var yyyy = dt.getFullYear();
  var mm = dt.getMonth() + 1;
  var dd = dt.getDate();
  var hh = dt.getHours();
  var nn = dt.getMinutes();
  var ss = dt.getSeconds();
  var datetime = yyyy + '-' + ( mm < 10 ? '0' : '' ) + mm + '-' + ( dd < 10 ? '0' : '' ) + dd
    + ' ' + ( hh < 10 ? '0' : '' ) + hh + ':' + ( nn < 10 ? '0' : '' ) + nn + ':' + ( ss < 10 ? '0' : '' ) + ss;
  return datetime;
}

function removeHtmlTag( html ){
  var text = html.replace(/<("[^"]*"|'[^']*'|[^'">])*>/g,'');
  text = text.split(',').join('');
  return text;
}


var port = settings.app_port || appEnv.port || 3000;
app.listen( port );
console.log( 'server started on ' + port );
