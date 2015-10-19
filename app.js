var express = require('express'),
    routes = require('./routes'),
    authCallback = require('./routes/auth-callback'),
    http = require('http'),
    path = require('path'),
    app = express(),
    // server info
    domain = "127.0.0.1",
    port = process.env.PORT || 3000,
    // passport / twitter stuff
    config = require('./config'),
    passport = require('passport'),
    TwitterStrategy = require('passport-twitter').Strategy,
    twitterAuthn,
    twitterAuthz,
    // poor man's database stub
    user = { id: "abc" },
    // oauth / twitter stuff
    OAuth= require('oauth').OAuth,
    oa;

function initTwitterOauth() {
  oa = new OAuth(
    "https://twitter.com/oauth/request_token",
    "https://twitter.com/oauth/access_token",
    config.consumerKey,
    config.consumerSecret,
    "1.0A",
    "http://" + domain + ":" + port + "/twitter/authn/callback",
    "HMAC-SHA1"
  );
}

function makeTweet(cb) {
  oa.post(
    "https://api.twitter.com/1.1/statuses/update.json",
    user.token,
    user.tokenSecret,
    {"status": "HELLO" },
    cb
  );
}

passport.serializeUser(function(_user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  done(null, user);
});

twitterAuthn = new TwitterStrategy({
    consumerKey: config.consumerKey,
    consumerSecret: config.consumerSecret,
    callbackURL: "http://" + domain + ":" + port + "/twitter/authn/callback"
  },
  function(token, tokenSecret, profile, done) {
    user.token = token;
    user.tokenSecret = tokenSecret;
    user.profile = profile;
    done(null, user);
  }
);

twitterAuthn.name = 'twitterAuthn';

twitterAuthz = new TwitterStrategy({
    consumerKey: config.consumerKey,
    consumerSecret: config.consumerSecret,
    callbackURL: "http://" + domain + ":" + port + "/twitter/authz/callback",
    userAuthorizationURL: 'https://api.twitter.com/oauth/authorize'
  },
  function(token, tokenSecret, profile, done) {
    user.token = token;
    user.tokenSecret = tokenSecret;
    user.profile = profile;
    user.authorized = true;
    initTwitterOauth();
    done(null, user);
  }
);
twitterAuthz.name = 'twitterAuthz';

passport.use(twitterAuthn);
passport.use(twitterAuthz);

// all environments
app.set('port', port);
app.set('views', __dirname + '/views');
app.set('view engine', 'jade');
app.use(express.favicon());
app.use(express.logger('dev'));
app.use(express.bodyParser());
app.use(express.methodOverride());
// Passport needs express/connect's cookieParser and session
app.use(express.cookieParser());
app.use(express.session({ secret: "blahhnsnhoaeunshtoe" }));
app.use(passport.initialize());
app.use(passport.session());
//  Passport MUST be initialize()d and session()d before the router
app.use(app.router);
app.use(express.static(path.join(__dirname, 'public')));

// development only
if ('development' === app.get('env')) {
  app.use(express.errorHandler());
}

app.get('/', routes.index);

app.get('/twitter/authn', passport.authenticate('twitterAuthn'));
app.get(
  '/twitter/authn/callback',
  passport.authenticate(
    'twitterAuthn',
    { failureRedirect: '/nfailure' }
  ),
  function (req, res) {
    // TODO if a direct message fails, remove this and try again
    // the user may have unauthorized the app
    if (!user.authorized) {
      res.redirect('/twitter/authz');
      return;
    }
    res.redirect('/auth-callback');
  }
);
app.get('/twitter/authz', passport.authenticate('twitterAuthz'));
app.get(
  '/twitter/authz/callback',
  passport.authenticate(
    'twitterAuthz',
    { successRedirect: '/zsuccess',
      failureRedirect: '/zfailure'
    }
  )
);
app.get('/twitter/tweet', function (req, res) {
  makeTweet(function (error, data) {
    if(error) {
      console.log(require('sys').inspect(error));
      res.end('bad stuff happened');
    } else {
      console.log(data);
      res.end('go check your tweets!');
    }
  });
});


function makeTweetVid(cb) {
  oa.post(
    "https://upload.twitter.com/1.1/media/upload.json",
    user.token,
    user.tokenSecret,
    {"media": "media/syria.mov" },
    cb
  );
}

app.get('/twitter/tweetvid', function (req, res) {
  makeTweetVid(function (error, data) {
    if(error) {
      console.log(require('sys').inspect(error));
      res.end('bad stuff happened');
    } else {
      console.log(data);
      res.end('go check your tweets!');
    }
  });
});

app.get('/auth-callback', authCallback.index);
app.post('/auth-callback', authCallback.index);

initTwitterOauth();
http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});
