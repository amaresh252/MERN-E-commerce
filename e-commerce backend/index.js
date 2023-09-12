const express = require('express');
const server = express();
const mongoose = require('mongoose');
const session =require('express-session');
const passport=require('passport');
const crypto=require('crypto');
const cookieParser=require('cookie-parser');
const productRouters=require('./routes/Products')
const categoriesRouter = require('./routes/Categories');
const brandsRouter = require('./routes/Brands');
const usersRouter = require('./routes/Users');
const authRouter = require('./routes/Auth');
const cartRouter = require('./routes/Cart');
const ordersRouter = require('./routes/Order');
const cors=require('cors');
const LocalStrategy=require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const   ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');

const { User } = require('./model/User');
const {isAuth,sanitizeUser,cookieExtractor}= require('./services/common')

const SECERT_KEY='SECERT_KEY';

const opts = {}
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = SECERT_KEY; 

server.use(express.static('build'))
server.use(cookieParser())
server.use(session({
    secret: 'keyboard cat',
    resave: false, 
    saveUninitialized: false, 
  }));
server.use(passport.authenticate('session'));
server.use(cors({
    exposedHeaders:['X-Total-Count']
}));
server.use(express.json());
server.use('/products',isAuth(),productRouters.router);
server.use('/categories',isAuth(),categoriesRouter.router);
server.use('/brands',isAuth(),brandsRouter.router);
server.use('/users',isAuth(), usersRouter.router)
server.use('/auth', authRouter.router)
server.use('/cart',isAuth(), cartRouter.router)
server.use('/orders',isAuth(), ordersRouter.router)

passport.use('local',new LocalStrategy(
    {usernameField:'email'},
   async   function(email, password, done) {
        try {
            
            const user = await User.findOne(
              { email: email }
            ).exec();
            if (!user) {
              done(null,false,{ message: 'invalid credentials' });
            }
            const salt = crypto.randomBytes(16);
            crypto.pbkdf2(
                password,
                user.salt,
                310000, 
                32, 
                'sha256',
            async function(err, hashedPassword){
              if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
               return done(null,false,{ message: 'invalid credentials' });
            } 
                const token = jwt.sign(sanitizeUser(user), SECERT_KEY);
                done(null,{id:user.id,role:user.role,token});
            
           });
          } catch (err) {
            done(err);
          }
      }
    
  ));

  passport.use('jwt',new JwtStrategy(opts, async function(jwt_payload, done) {

    try{
        const user= await User.findById( jwt_payload.id);
        if (user) {
            return done(null, sanitizeUser(user));
        } else {
            return done(null, false);
           
        }
    
    }catch(err){
        return done(err, false);
    }
}));
  passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {id:user.id, role:user.role});
    });
  }); 
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });



main().catch(err=> console.log(err));

async function main(){
    await mongoose.connect('mongodb+srv://ecoomerceDB:b43g9TvTuCuaixza@cluster0.y9hdlv4.mongodb.net/ecommerce?retryWrites=true&w=majority');
    console.log('database connected')   
}





server.listen(8080, ()=>{
    console.log('server started')
});