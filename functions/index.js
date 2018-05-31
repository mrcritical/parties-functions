const functions = require('firebase-functions');
const admin = require('firebase-admin');
const app = require('express')();
const serviceAccount = require('./service-account.json');
const firebaseAccount = require('./firebase-account.json');
const firebase = require('firebase');
const cookieParser = require('cookie-parser')();
const cors = require('cors')({origin: true});

const adminApp = admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: 'https://parties-35d88.firebaseio.com'
});
const firebaseApp = firebase.initializeApp(firebaseAccount);

// Express middleware that validates Firebase ID Tokens passed in the Authorization HTTP header.
// The Firebase ID token needs to be passed as a Bearer token in the Authorization HTTP header like this:
// `Authorization: Bearer <Firebase ID Token>`.
// when decoded successfully, the ID Token content will be added as `req.user`.
const validateFirebaseIdToken = (req, res, next) => {
    console.log('Check if request is authorized with Firebase ID token');

    if ((!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) &&
        !(req.cookies && req.cookies.__session)) {
        console.error('No Firebase ID token was passed as a Bearer token in the Authorization header.',
            'Make sure you authorize your request by providing the following HTTP header:',
            'Authorization: Bearer <Firebase ID Token>',
            'or by passing a "__session" cookie.');
        res.status(403).send('Unauthorized');
        return;
    }

    let idToken;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        console.log('Found "Authorization" header');
        // Read the ID Token from the Authorization header.
        idToken = req.headers.authorization.split('Bearer ')[1];
    } else if(req.cookies) {
        console.log('Found "__session" cookie');
        // Read the ID Token from cookie.
        idToken = req.cookies.__session;
    } else {
        // No cookie
        res.status(403).send('Unauthorized');
        return;
    }
    admin.auth().verifyIdToken(idToken).then((decodedIdToken) => {
        console.log('ID Token correctly decoded', decodedIdToken);
        req.user = decodedIdToken;
        return next();
    }).catch((error) => {
        console.error('Error while verifying Firebase ID token:', error);
        res.status(403).send('Unauthorized');
    });
};

app.use(cors);
app.use(cookieParser);

/**
 * Authorizes a link for a specific attendee. If authorized, returns a token for login to Firebase.
 * Links send to the attendees should go to
 * https://us-central1-parties-35d88.cloudfunctions.net/api/attendee/authorize?token={email-token}.
 */
app.get('/attendee/authorize', (req, res) => {
    const token = req.query.token;
    adminApp
        .firestore()
        .collection('tokens')
        .doc(token)
        .get()
        .then(attendee => {
            const data = attendee.data();
            if (attendee.exists) {
                return Promise.all([
                    attendee,
                    adminApp
                        .auth()
                        .createCustomToken(data.userId)
                ])
            } else {
                return Promise.reject(new Error('Failed to find the uid for attendee using token=' + token));
            }
        })
        .then(results => {
            const attendee = results[0];
            const customToken = results[1];
            return res.json({
                id: attendee.data().userId,
                token: customToken
            });
        })
        .catch((error) => {
            console.error('An invalid token=' + token + ' was received', error);
            return res
                .status(403)
                .send();
        });
});

app.post('/party/:partyId/attendee-login-link', (req, res) => {
    console.log('Body: ' + JSON.stringify(req.body));
    const partyId = req.params.partyId;
    const email = req.body.email;
    return firebaseApp
        .auth()
        .sendSignInLinkToEmail(email, {
            // URL you want to redirect back to. The domain (www.example.com) for this
            // URL must be whitelisted in the Firebase Console.
            url: 'http://localhost:3000/parties/' + partyId + '?email=' + email,
            // This must be true.
            handleCodeInApp: true
        })
        .then(() => {
            return res
                .status(202)
                .send();
        })
        .catch(error => {
            return res
                .status(500)
                .json(error);
        });
});

exports.api = functions.https.onRequest(app);