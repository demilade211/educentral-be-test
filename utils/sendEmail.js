import dotenv from "dotenv"; 
const { MailtrapClient } = require("mailtrap");

dotenv.config({ path: "config/config.env" });



// const DOMAIN = process.env.MAILGUN_DOMAIN;
// const api_key = process.env.MAILGUN_API_KEY
// const { OAuth2 } = google.auth;
// const OAUTH_PLAYGROUND = 'https://developers.google.com/oauthplayground/'  

// const {
//   MAILING_SERVICE_CLIENT_ID,
//   MAILING_SERVICE_CLIENT_SECRET,
//   MAILING_SERVICE_REFRESH_TOKEN,
//   SENDER_EMAIL_ADDRESS

// } = process.env

// const oauth2Client = new OAuth2(
//   MAILING_SERVICE_CLIENT_ID,
//   MAILING_SERVICE_CLIENT_SECRET,
//   MAILING_SERVICE_REFRESH_TOKEN,
//   OAUTH_PLAYGROUND
// )

const sendEmail = async (options) => {



  const TOKEN = "e11974ddce280b7d7a4b3d7c42e939d8";
  const ENDPOINT = "https://send.api.mailtrap.io/";

  const client = new MailtrapClient({ endpoint: ENDPOINT, token: TOKEN });

  const sender = {   email: "noreply@tuale.app" };

  await client.send({
    from: sender,
    to: [{ email: options.email }],
    subject: options.subject,
    text: options.message,
  }) 


  // oauth2Client.setCredentials({
  //   refresh_token: MAILING_SERVICE_REFRESH_TOKEN
  // })

  // const accessToken = oauth2Client.getAccessToken()
  // const smtpTransport = nodemailer.createTransport({
  //   service: 'gmail',
  //   secure: false, // use SSL
  //   auth: {
  //     type: 'OAuth2',
  //     user: SENDER_EMAIL_ADDRESS,
  //     clientId: MAILING_SERVICE_CLIENT_ID,
  //     clientSecret: MAILING_SERVICE_CLIENT_SECRET,
  //     refreshToken: MAILING_SERVICE_REFRESH_TOKEN,
  //     accessToken
  //   },
  //   tls: {
  //     rejectUnauthorized: false
  //   }
  // })

  // const mailOptions = {
  //   from: SENDER_EMAIL_ADDRESS,
  //   to: options.email,
  //   subject: options.subject,
  //   html: options.message  
  // }

  // await smtpTransport.sendMail(mailOptions)


  // smtpTransport.sendMail(mailOptions, (err, infor) => {
  //     if(err) return err;
  //     return infor
  // })


  // Using my email
  // var transporter = nodemailer.createTransport({
  //     service: 'gmail',
  //     secure: false, // use SSL
  //     auth: {
  //       user: process.env.NODEMAILER_USERNAME,
  //       pass: process.env.NODEMAILER_PASSWORD
  //     },
  //     tls: {
  //         rejectUnauthorized: false
  //     }
  //   });

  //   var mailOptions = {
  //     from: process.env.NODEMAILER_USERNAME,
  //     to: options.email,
  //     subject: options.subject,
  //     text: options.message
  //   };


  // await transporter.sendMail(mailOptions)


  //mailgun
  // const mg = mailgun({apiKey: api_key, domain: DOMAIN});
  // const data = { 
  //   from: 'tulenoreply@gmail.com',
  //   to: options.email,
  //   subject: options.subject,
  //   text: options.message
  // };

  // await mg.messages().send(data)

}

export default sendEmail;