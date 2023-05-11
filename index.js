// Include the cluster module
var cluster = require('cluster');

// Code to run if we're in the master process
if (cluster.isMaster) {

  // Count the machine's CPUs
  var cpuCount = require('os').cpus().length;

  // Create a worker for each CPU
  for (var i = 0; i < cpuCount; i += 1) {
    cluster.fork();
  }

  // Listen for terminating workers
  cluster.on('exit', function (worker) {

    // Replace the terminated workers
    console.log('Worker ' + worker.id + ' died :(');
    cluster.fork();

  });

  // Code to run if we're in a worker process
} else {

  require('dotenv').config()
  const express = require('express')
  const bodyParser = require('body-parser')
  const crypto = require('crypto')
  const fetch = require('node-fetch')
  // Use the request module to make HTTP requests from Node
  const request = require('request')

  // AWS params
  const AWS = require('aws-sdk')
  const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_CLIENT_ID,
    secretAccessKey: process.env.AWS_CLIENT_SECRET,
    region: process.env.AWS_REGION
  });
  const awsConfig = {
    accessKeyId: process.env.AWS_CLIENT_ID,
    secretAccessKey: process.env.AWS_CLIENT_SECRET,
    region: process.env.AWS_REGION
  }
  AWS.config.update(awsConfig);
  // AWS.config.region = process.env.AWS_REGION
  var sns = new AWS.SNS();
  var ddb = new AWS.DynamoDB();
  var ddbTable = process.env.USERS_TABLE;
  var ddbTable2 = process.env.MEETINGS_TABLE;
  var ddbTable3 = process.env.WAITLIST_TABLE;
  var snsTopic = process.env.SIGNUP_TOPIC;
  var gongSnsTopic = process.env.GONG_RECORDING_TOPIC

  // Deepgram params
  const { Deepgram } = require("@deepgram/sdk");
  const deepgram = new Deepgram(process.env.DEEPGRAM_API_KEY);

  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', __dirname + '/views');
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: false }));
  // app.use(express.static('public'))
  app.use(express.static(__dirname + '/public'));

  app.get('/', (req, res) => {
    res.render('index', {
      static_path: '/static',
      theme: process.env.THEME || 'default',
      flask_debug: process.env.FLASK_DEBUG || 'false',
      client_id: process.env.clientID,
      redirect_url: process.env.redirectURL,
      redirect: 'false'
    });
    // res.send(`Webhook Sample Node.js successfully running. Set this URL with the /webhook path as your apps Event notification endpoint URL. https://github.com/zoom/webhook-sample-node.js`)
    // TODO(erajain): move check whitelisted user flow here. If user is whitelisted, call
    // https://zoom.us/oauth/authorize?response_type=code&client_id=<client id>&redirect_uri=<redirect url>
    // Under Zoom App configurations, use authenticate from site
  })

  app.post('/verify', (req, res) => {
    const email = req.body.email;
    const name = req.body.name
    console.log("email: " + email)
    console.log("name: " + name)
    var params = {
      Key: {
        "email": {
          S: email
        }
      },
      TableName: ddbTable
    }
    ddb.getItem(params, function (err, data) {
      if (err) {
        res.status(500).end();
        console.log(err, err.stack);
      } else if (data.Item) {
        console.log("Email found");
        res.sendStatus(201);
      } else {
        // User not whitelisted.
        let date_ob = new Date();
        var newItem = {
          'email': { 'S': email },
          'date': { 'S': date_ob.toISOString() },
        };
        ddb.putItem({
          'TableName': ddbTable3,
          'Item': newItem,
        }, function (err, data) {
          if (err) {
            console.log(err);
          } else {
            res.status(410).end();
          }
        });
      }
    });
  });

  // Logic - allow 1 free summarization. If already a pilot user great. Else show a message to contact to get started with the free trial
  app.post('/summarize', (req, res) => {
    const email = req.body.emailGong;
    const link = req.body.link;
    console.log("email: " + email)
    console.log("link: " + link)
    var params = {
      Key: {
        "email": {
          S: email
        }
      },
      TableName: ddbTable
    }
    // 1. Put item if email doesn't exist
    // 2. If exist, check no. of recordings - you get 1 free.
    ddb.getItem(params, function (err, data) {
      if (err) {
        console.log(err, err.stack);
        res.status(500).end();
      } else if (data.Item) {
        console.log("Email found");
        let date_ob = new Date();
        sns.publish({
          'Message': 'Email: ' + email + '\r\nDate: ' + date_ob.toISOString() + '\r\nRecording link: ' + link,
          'Subject': 'New Gong Recording received',
          'TopicArn': gongSnsTopic
        }, function (err, data) {
          if (err) {
            console.log('SNS Error: ' + err);
            res.status(500).end();
          } else {
            console.log("Gong recording sent!");
            res.status(201).end();
          }
        });
        // TODO: Extract download link from link
        // Put it in ddbGongTable - email,date,link
        // domain = link.split("/e")[0]
        // companySpeakers, nonCompanySpeakers, unclassifiedSpeakers, videoURL
        // head -> script -> pageData
        res.status(201).end();
      } else {
        // User not whitelisted.
        let date_ob = new Date();
        var newItem = {
          'email': { 'S': email },
          'date': { 'S': date_ob.toISOString() },
        };
        ddb.putItem({
          'TableName': ddbTable3,
          'Item': newItem,
        }, function (err, data) {
          if (err) {
            console.log(err);
          } else {
            res.status(410).end();
          }
        });
        res.status(410).end();
      }
    });
  });

  app.get('/zoomverify/verifyzoom.html', (req, res) => {
    res.send(process.env.zoom_verification_code)
  })

  app.get('/terms-of-use', (req, res) => {
    res.writeHead(301, { Location: "https://www.getdeepinsights.com/terms-of-use" });
    res.end()
  })

  app.get('/privacy-policy', (req, res) => {
    res.writeHead(301, { Location: "https://www.getdeepinsights.com/privacy-policy" });
    res.end()
  })

  app.get('/contact-us', (req, res) => {
    res.writeHead(301, { Location: "https://www.getdeepinsights.com/contact-us" });
    res.end()
  })

  app.get('/documentation', (req, res) => {
    res.writeHead(301, { Location: "https://valley-beat-d42.notion.site/DeepInsights-Note-Taker-Beta-for-Zoom-6ac78d43f8604b3793f7bc0139ba4688" });
    res.end()
  })

  app.get('/auth/token', (req, res) => {
    // Step 1: Check if it's an Oauth request
    // Check if the code parameter is in the url 
    // if an authorization code is available, the user has most likely been redirected from Zoom OAuth
    // if not, the user needs to be redirected to Zoom OAuth to authorize

    if (req.query.code) {
      // Step 3: 
      // Request an access token using the auth code
      let url = 'https://zoom.us/oauth/token?grant_type=authorization_code&code=' + req.query.code + '&redirect_uri=' + process.env.redirectURL;

      request.post(url, (error, response, body) => {

        // Parse response to JSON
        body = JSON.parse(body);

        // Logs your access and refresh tokens in the browser
        console.log(`access_token: ${body.access_token}`);
        console.log(`refresh_token: ${body.refresh_token}`);
        var refresh_token = body.refresh_token;

        if (body.access_token) {

          // Step 4:
          // We can now use the access token to authenticate API calls

          // Send a request to get your user information using the /me context
          // The `/me` context restricts an API call to the user the token belongs to
          // This helps make calls to user-specific endpoints instead of storing the userID
          // TODO(erajain): If body.email is a whitelisted pilot user, redirect them to the login page,
          //                and have them sign in using the passcode initially emailed to them when they
          //                start the pilot. They can change their passwords later.
          //                The app currently only has the integration page, that can be toggled on and off.
          request.get('https://api.zoom.us/v2/users/me', (error, response, body) => {
            if (error) {
              console.log('API Response Error: ', error)
            } else {
              body = JSON.parse(body);
              var username = body.first_name + " " + body.last_name
              // var item = {
              //   'email': { 'S': body.email },
              //   'name': { 'S': username },
              //   'zoom_host_id': { 'S': body.id },
              //   'zoom_refresh_token': { 'S': refresh_token }
              // };
              var ddbparams = {
                TableName: ddbTable,
                ExpressionAttributeNames: {
                  "#N": "name",
                  "#ZH": "zoom_host_id",
                  "#ZR": "zoom_refresh_token",
                },
                ExpressionAttributeValues: {
                  ":t": {
                    S: username
                  },
                  ":y": {
                    S: body.id
                  },
                  ":z": {
                    S: refresh_token
                  },
                },
                Key: {
                  "email": {
                    S: body.email
                  }
                },
                UpdateExpression: "SET #N = :t, #ZH = :y, #ZR = :z"
              }
              ddb.updateItem(ddbparams, function (err, data) {
                if (err) {
                  var returnStatus = 500;

                  if (err.code === 'ConditionalCheckFailedException') {
                    returnStatus = 409;
                  }

                  console.log(returnStatus);
                  console.log('DDB Error: ' + err);
                  res.render('index', {
                    static_path: '/static',
                    theme: process.env.THEME || 'default',
                    flask_debug: process.env.FLASK_DEBUG || 'false',
                    client_id: process.env.clientID,
                    redirect_url: process.env.redirectURL,
                    redirect: 'true',
                    status: returnStatus
                  });
                  res.status(returnStatus).end();
                } else {
                  sns.publish({
                    'Message': 'Name: ' + username + "\r\nEmail: " + body.email,
                    'Subject': 'New pilot user sign up!!!',
                    'TopicArn': snsTopic
                  }, function (err, data) {
                    if (err) {
                      res.render('index', {
                        static_path: '/static',
                        theme: process.env.THEME || 'default',
                        flask_debug: process.env.FLASK_DEBUG || 'false',
                        client_id: process.env.clientID,
                        redirect_url: process.env.redirectURL,
                        redirect: 'true',
                        status: 500
                      });
                      res.status(500).end();
                      console.log('SNS Error: ' + err);
                    } else {
                      console.log("Registered!");
                      res.render('index', {
                        static_path: '/static',
                        theme: process.env.THEME || 'default',
                        flask_debug: process.env.FLASK_DEBUG || 'false',
                        client_id: process.env.clientID,
                        redirect_url: process.env.redirectURL,
                        redirect: 'true',
                        status: 201
                      });
                      res.status(201).end();
                    }
                  });
                }
              });
            }
          }).auth(null, null, true, body.access_token);

        } else {
          res.status(500);
          console.log("Cannot parse the authentication response");
        }

      }).auth(process.env.clientID, process.env.clientSecret);

      return;

    }

    // Step 2: 
    // If no authorization code is available, redirect to Zoom OAuth to authorize
    res.redirect('https://zoom.us/oauth/authorize?response_type=code&client_id=' + process.env.clientID + '&redirect_uri=' + process.env.redirectURL)
  })

  app.post('/webhook', async (req, res) => {

    var response

    console.log(req.body)
    console.log(req.headers)

    // construct the message string
    const message = `v0:${req.headers['x-zm-request-timestamp']}:${JSON.stringify(req.body)}`

    const hashForVerify = crypto.createHmac('sha256', process.env.ZOOM_WEBHOOK_SECRET_TOKEN).update(message).digest('hex')

    // hash the message string with your Webhook Secret Token and prepend the version semantic
    const signature = `v0=${hashForVerify}`

    // you validating the request came from Zoom https://marketplace.zoom.us/docs/api-reference/webhook-reference#notification-structure
    if (req.headers['x-zm-signature'] === signature) {

      // Zoom validating you control the webhook endpoint https://marketplace.zoom.us/docs/api-reference/webhook-reference#validate-webhook-endpoint
      if (req.body.event === 'endpoint.url_validation') {
        const hashForValidate = crypto.createHmac('sha256', process.env.ZOOM_WEBHOOK_SECRET_TOKEN).update(req.body.payload.plainToken).digest('hex')

        response = {
          message: {
            plainToken: req.body.payload.plainToken,
            encryptedToken: hashForValidate
          },
          status: 200
        }

        console.log(response.message)

        res.status(response.status)
        res.json(response.message)
      } else {
        response = { message: 'Authorized request to Webhook Sample Node.js.', status: 200 }

        console.log(response.message)
        res.status(response.status)
        res.json(response)
        // if (req.body.event === 'meeting.started') {
        //   // var user_id = req.body.payload.object.host_id
        //   // Retrieve zoom_code, email for user_id from the database
        //   // var access_token = req.headers.authorization;
        //   var email = EMAIL;
        //   var chat_json = {
        //     "at_items": [
        //       {
        //         "at_contact": `${email}`,
        //         "at_type": 2,
        //         "end_position": 8,
        //         "start_position": 0
        //       }
        //     ],
        //     "rich_text": [
        //       {
        //         "start_position": 0,
        //         "end_position": 1,
        //         "format_type": "Paragraph",
        //         "format_attr": "h1"
        //       }
        //     ],
        //     "message": "Start recording the meeting to enable DeepInsights notes",
        //     "to_contact": `${email}`
        //   }
        //   let url = 'https://zoom.us/oauth/token?grant_type=refresh_token&refresh_token=' + REFRESH_TOKEN;
        //   request.post(url, (error, response, body) => {

        //     // Parse response to JSON
        //     body = JSON.parse(body);

        //     // Logs your access and refresh tokens in the browser
        //     console.log(`access_token: ${body.access_token}`);
        //     console.log(`refresh_token: ${body.refresh_token}`);
        //     REFRESH_TOKEN = body.refresh_token
        //     if (body.access_token) {
        //       fetch(`https://api.zoom.us/v2/chat/users/me/messages`, {
        //         method: "POST",
        //         headers: {
        //           Authorization: `Bearer ${body.access_token}`,
        //           "Content-Type": "application/json",
        //         },
        //         body: JSON.stringify(chat_json),
        //       }).then(res => res.json())
        //         .then(json => console.log(json))
        //         .catch(err => console.log(err));
        //     } else {
        //       console.log("Cannot refresh access_token: ", error);
        //       // Handle errors, something's gone wrong!
        //     }
        //   }).auth(process.env.clientID, process.env.clientSecret);
        // }
        // business logic here, example make API request to Zoom or 3rd party
        // if (req.body.event === 'recording.started') {
        // const meeting_id = req.body.payload.object.id
        // console.log("Meeting Id: ", meeting_id);
        // try {
        //   const participants = await getMeetingParticipants(meeting_id);
        //   console.log(participants);
        // } catch (e) {
        //   console.log(e);
        // }
        // fetchPromise.then(res => res.json())
        //   .then(json => console.log(json))
        //   .catch(err => console.log(err));
        // const fetchPromise = await getMeetingParticipants(meeting_id);
        // fetchPromise.then(res => {
        //   body = res.json();
        //   console.log(body);
        // }).catch(err => console.log(err));
        // }
        if (req.body.event === 'app_deauthorized') {
          console.log("Zoom App Remove for user: ", req.body.payload.user_id)
          console.log("Time of removal: ", req.body.payload.deauthorization_time);
        }
        if (req.body.event === 'meeting.chat_message_sent') {
          console.log(req.body.payload.object.chat_message);
        }
        // Get download_url for the each recording of the meeting.
        if (req.body.event === 'recording.completed') {
          const object = req.body.payload.object;
          // Get user's name and zoom_token
          var params = {
            Key: {
              "email": {
                S: object.host_email
              }
            },
            TableName: ddbTable
          }
          ddb.getItem(params, function (err, data) {
            if (err) {
              console.log("Dynamodb getItem error: ", err);
            } else if (data.Item) {
              console.log(data.Item);
              const username = data.Item.name.S;
              deactivate = false;
              if (data.Item.hasOwnProperty('deactivate')) {
                deactivate = data.Item.deactivate.BOOL;
              }
              // var refresh_token = data.Item.refresh_token;
              let boost_keywords = [];
              if (data.Item.hasOwnProperty('boost_keywords')) {
                boost_keywords = data.Item.boost_keywords.SS;
              }
              var meeting_id = "" + object.id
              var newItem = {
                'meeting_uuid': { 'S': object.uuid },
                'email': { 'S': object.host_email },
                'disable': { 'BOOL': deactivate },
                'processed': { 'BOOL': false},
              };
              ddb.putItem({
                'TableName': ddbTable2,
                'Item': newItem,
              }, function (err, data) {
                console.log(err);
              });
              // Make an api call to fetch meeting participants
              // const meeting_id = object.id
              // console.log("Meeting Id: ", meeting_id);
              //   const fetchPromise = await getMeetingParticipants(meeting_id, refresh_token, email);
              //   fetchPromise.then(res => res.json())
              //   .then(json => {
              //     console.log(json);
              //     for (let i = 0 ; i < json.total_records; i++) { 
              //       metadata.participant_names = metadata.participant_names + json.participants[i].name + ",";
              //       metadata.participant_emails = metadata.participant_emails + json.participants[i].user_email + ",";
              //     }
              //     console.log(metadata);
              //   }).catch(err => console.log(err));
              const download_token = req.body.download_token
              const meeting_name = username + "/" + object.topic + '_' + object.start_time
              var metadata = {
                "meeting_name": object.topic,
                "meeting_id": meeting_id,
                "uuid": object.uuid,
                "meeting_start_time": object.start_time,
                "timezone": object.timezone,
                "host_email": object.host_email,
                // "participant_names": '',
                // "participant_emails": '',
              }
              if (object.participant_audio_files) {
                // Get participant first names for boost in transcription
                const len = Math.min(object.participant_audio_files.length, 100);
                for (let index = 0; index < len; index++) {
                  p_name = object.participant_audio_files[index].file_name.replace("Audio only - ", "");
                  console.log(p_name.split(' ')[0]);
                  boost_keywords.push(p_name.split(' ')[0]);
                }
                for (let index = 0; index < object.participant_audio_files.length; index++) {
                  const element = object.participant_audio_files[index];
                  if (element.status !== 'completed' || element.file_type !== 'M4A') {
                    console.log("recording status not completed or not a m4a")
                  } else {
                    content_type = 'audio/m4a'
                    extension = 'm4a'
                    key = meeting_name + "/" + element.file_name + '.' + extension
                    download_url_with_token = element.download_url + "?access_token=" + download_token
                    try {
                      // console.log("uploadZoomFiletoS3 for ", meeting_name);
                      uploadZoomFileToS3(element, metadata, download_url_with_token, key, content_type);
                      transcribeByParticipantAndUploadToS3(download_url_with_token, meeting_name, element.file_name, metadata, boost_keywords);
                    } catch (err) {
                      console.log(err);
                    }
                  }
                }
              }
              const recording_files = object.recording_files
              const len2 = Math.min(recording_files.length, 100);
              for (let index = 0; index < len2; index++) {
                // TODO(erajain): add code to make sure all parts of the recordings are uploaded? Or just the longest recording is uploaded?
                // TODO(erajain): add code for transcripts, chats.
                const element = recording_files[index];
                console.log(element);
                if (element.status !== 'completed' || element.file_type === 'M4A') {
                  console.log("recording status not completed or not a mp4 or not a chat file")
                } else if (element.file_type === 'CHAT') {
                  // Check if disable DI then don't record.
                  download_url_with_token = element.download_url + "?access_token=" + download_token
                  try {
                    checkIfDisableDI(object.host_email, object.uuid, download_url_with_token);
                  } catch (err) {
                    console.log(err);
                  }
                } else if (element.file_type === 'MP4') {
                  content_type = 'video/mp4'
                  extension = 'mp4'
                  key = meeting_name + "/full_recording." + extension
                  download_url_with_token = element.download_url + "?access_token=" + download_token
                  try {
                    // console.log("uploadZoomFiletoS3 for ", meeting_name);
                    uploadZoomFileToS3(element, metadata, download_url_with_token, key, content_type);
                    transcribeAndUploadToS3(download_url_with_token, meeting_name, "full_recording", metadata, boost_keywords);
                  } catch (err) {
                    console.log(err);
                  }
                }
              }
            } else {
              console.log('No Item found matching email:', object.host_email);
            }
          });
        }
        if (req.body.event === 'recording.transcript_completed') {
          const object = req.body.payload.object;
          var params = {
            Key: {
              "email": {
                S: object.host_email
              }
            },
            TableName: ddbTable
          }
          ddb.getItem(params, async function (err, data) {
            if (err) {
              console.log("Dynamodb getItem error: ", err);
            } else if (data) {
              const download_token = req.body.download_token
              const username = data.Item.name.S;
              const meeting_name = username + "/" + object.topic + '_' + object.start_time
              var metadata = {
                "meeting_name": object.topic,
                "uuid": object.uuid,
                "meeting_start_time": object.start_time,
                "timezone": object.timezone,
                "host_email": object.host_email,
              }
              const recording_files = object.recording_files
              const len3 = Math.min(recording_files.length, 100)
              for (let index = 0; index < len3; index++) {
                element = recording_files[index];
                if (element.status !== 'completed' || element.file_type !== 'TRANSCRIPT') {
                  console.log("recording status not completed or not a transcript.")
                } else {
                  content_type = 'text/plain'
                  extension = 'txt'
                  key = meeting_name + "/transcript." + extension
                  download_url_with_token = element.download_url + "?access_token=" + download_token
                  try {
                    uploadZoomFileToS3(element, metadata, download_url_with_token, key, content_type);
                  } catch (err) {
                    console.log(err);
                  };
                }
              }
            } else {
              console.log('No Item found matching email:', object.host_email);
            }
          });
        }
      }
    } else {
      response = { message: 'Unauthorized request to Webhook Sample Node.js.', status: 401 }

      console.log(response.message)

      res.status(response.status)
      res.json(response)
    }
  })

  async function checkIfDisableDI(host_email, meeting_uuid, download_url_with_token) {
    request.get(`${download_url_with_token}`, function (error, response, body) {
      if (!error && response.statusCode == 200) {
        var chat_str = String(body).toLowerCase();
        console.log(chat_str);
        if (chat_str.includes('disable di') ||
          chat_str.includes('disable deepinsights') ||
          chat_str.includes('disable deepinsight') ||
          chat_str.includes('disable deep insight') ||
          chat_str.includes('disable deep insights')) {
          var item = {
            'meeting_uuid': { 'S': meeting_uuid },
            'email': { 'S': host_email },
            'disable': { 'BOOL': true },
            'processed': { 'BOOL': false},
          };
          ddb.putItem({
            'TableName': ddbTable2,
            'Item': item,
          }, function (err, data) {
            console.log(err);
          });
        }
      } else if (error) {
        console.log(error);
      }
    });
  }

  // TODO(erajain): Figure out AWS timeout issues (flaky)
  async function uploadZoomFileToS3(element, metadata, download_url_with_token, key, content_type) {
    console.log(element)
    metadata["recording_start"] = element.recording_start
    metadata["recording_end"] = element.recording_end

    return new Promise((resolve, reject) => {
      fetch(`${download_url_with_token}`, {
        method: 'GET',
        redirect: 'follow'
      })
        .then(response => {
          const request = s3.upload({
            Bucket: process.env.AWS_BUCKET_NAME,
            Key: key,
            Body: response.body,
            ContentType: content_type,
            ContentLength: element.file_size || Number(response.headers.get('content-length')),
            Metadata: metadata,
          });
          return request.promise();
        })
        .then(data => {
          console.log(`Successfully uploaded ${key}.`);
          resolve(data);
        }).catch(error => reject(error));
    });
  }

  async function transcribeAndUploadToS3(downloadUrl, meeting_name, filename, metadata, boost_keywords) {
    const fileSource = { url: downloadUrl };
    const s3_key = meeting_name + "/" + filename + "_transcript.txt";
    const s3_key2 = meeting_name + "/" + filename + "_utt.txt";
    return new Promise((resolve, reject) => {
      deepgram.transcription.preRecorded(fileSource, {
        punctuate: true,
        language: 'en',
        model: 'meeting',
        diarize: true,
        numerals: true,
        utterances: true,
        keywords: boost_keywords,
      }).then((response) => {
        // const srtTranscript = response.toSRT()
        const diarized_transcript = combineUttsBySpeakers(response);
        // TODO: Make utt all lower case
        getUttToSpeakerMapFile(response, metadata.uuid);
        const request1 = s3.upload({
          Bucket: process.env.AWS_BUCKET_NAME,
          Key: s3_key,
          Body: diarized_transcript,
          ContentLength: diarized_transcript.length,
          ContentType: 'plain/txt',
          Metadata: metadata,
        });
        return request1.promise()
        // const request2 = s3.putObject({
        //   Bucket: process.env.AWS_BUCKET_NAME,
        //   Key: s3_key2,
        //   Body: utts_by_speaker_map,
        //   ContentType: 'plain/txt',
        //   Metadata: metadata,
        // });
        // return request1.promise(), request2.promise();
      }).then(data => {
        console.log(`Successfully uploaded ${s3_key}.`);
        // console.log(`Successfully uploaded ${s3_key2}.`);
        resolve(data);
      }).catch((error) => {
        console.log("Couldn't transcribe: ", s3_key, error);
        reject(error);
      });
    });
  }

  async function transcribeByParticipantAndUploadToS3(downloadUrl, meeting_name, filename, metadata, boost_keywords) {
    const fileSource = { url: downloadUrl };
    const s3_key = meeting_name + "/" + filename + "_utt.txt";
    // Adding participant name as the top row.
    var name = filename.replace("Audio only - ", "");
    var utts = "";
    return new Promise((resolve, reject) => {
      deepgram.transcription.preRecorded(fileSource, {
        punctuate: true,
        language: 'en',
        model: 'meeting',
        // diarize: true,
        numerals: true,
        utterances: true,
        keywords: boost_keywords,
      }).then((response) => {
        for (let i = 0; i < response.results.utterances.length; i++) {
          utts = utts + response.results.utterances[i].transcript.toLowerCase() + "-->" + name + "\n";
        }
        key_name = "utt_to_name_" + name 
        var ddbparams = {
          TableName: ddbTable2,
          ExpressionAttributeNames: {
            "#UN": key_name,
          },
          ExpressionAttributeValues: {
            ":v": {
              S: utts
            },
          },
          Key: {
            "meeting_uuid": {
              S: metadata.uuid
            }
          },
          UpdateExpression: "SET #UN = :v"
        }
        ddb.updateItem(ddbparams, function (err, data) {
          if (err) {
            console.log('DDB Error: ' + err);
          }
        })
        // const request = s3.putObject({
        //   Bucket: process.env.AWS_BUCKET_NAME,
        //   Key: s3_key,
        //   Body: utts,
        //   ContentType: 'plain/txt',
        //   Metadata: metadata,
        // });
        // return request.promise();
      }).then(data => {
        console.log(`Successfully uploaded ${s3_key}.`);
        resolve(data);
      }).catch((error) => {
        console.log("Couldn't transcribe: ", s3_key, error);
        reject(error);
      });
    });
  }

  function getUttToSpeakerMapFile(response, meeting_uuid) {
    var utts = "";
    for (let i = 0; i < response.results.utterances.length; i++) {
      utts = utts + response.results.utterances[i].transcript.toLowerCase() + "-->speaker" + response.results.utterances[i].speaker + "\n";
    }
    var ddbparams = {
      TableName: ddbTable2,
      ExpressionAttributeNames: {
        "#US": "utt_to_speaker",
      },
      ExpressionAttributeValues: {
        ":v": {
          S: utts
        },
      },
      Key: {
        "meeting_uuid": {
          S: meeting_uuid
        }
      },
      UpdateExpression: "SET #US = :v"
    }
    ddb.updateItem(ddbparams, function (err, data) {
      if (err) {
        console.log('DDB Error: ' + err);
      }
    })
  }

  function combineUttsBySpeakers(response) {
    // console.log(response.results)
    // console.log(response.results.utterances[0]);
    // console.log(response.results.utterances[1]);
    if (response.results.utterances.length >= 1) {
      var prev_speaker = response.results.utterances[0].speaker
      var utt = response.results.utterances[0].transcript
      var start = new Date(response.results.utterances[0].start * 1000).toISOString().substr(11, 12)
      var end = new Date(response.results.utterances[0].end * 1000).toISOString().substr(11, 12)
      var transcript = "";
      if (response.results.utterances.length == 1) {
        transcript = "speaker" + prev_speaker + "\t" + start + "-->" + end + "\n" + utt + "\n\n"
        return transcript;
      }
      for (let i = 1; i < response.results.utterances.length; i++) {
        const utterance = response.results.utterances[i]
        // console.log(utterance.transcript)
        if (utterance.speaker == prev_speaker) {
          utt = utt + " " + utterance.transcript
          end = new Date(utterance.end * 1000).toISOString().substr(11, 12)
        } else {
          transcript = transcript + "speaker" + prev_speaker + "\t" + start + "-->" + end + "\n" + utt + "\n\n"
          console.log(transcript)
          utt = utterance.transcript
          start = new Date(utterance.start * 1000).toISOString().substr(11, 12)
          end = new Date(utterance.end * 1000).toISOString().substr(11, 12)
        }
        prev_speaker = utterance.speaker
      }
      transcript = transcript + "speaker" + prev_speaker + "\t" + start + "-->" + end + "\n" + utt + "\n\n"
      // console.log(transcript);
      return transcript;
    } else {
      return "";
    }
  }

  async function getRefreshToken(refresh_token, email) {
    let url = 'https://zoom.us/oauth/token?grant_type=refresh_token&refresh_token=' + refresh_token;
    request.post(url, (error, response, body) => {
      if (error) {
        console.log("Couldn't refresh access token", error);
        return error;
      }
      try {
        body = JSON.parse(body);
        console.log(`access_token: ${body.access_token}`);
        console.log(`refresh_token: ${body.refresh_token}`);
        // TODO(erajain): Get item from DB table using email and update refresh_token to body.refresh_token
        return body.access_token;
      } catch (e) {
        console.log("Couldn't parse json:", e);
        return e;
      }
    }).auth(process.env.clientID, process.env.clientSecret);
  }

  // TODO(erajain): Do better with async, await, and promise.
  // TODO(erajain): Do better with error logging.
  async function getMeetingParticipants(meeting_id, refresh_token, email) {
    let url = 'https://zoom.us/oauth/token?grant_type=refresh_token&refresh_token=' + refresh_token;
    request.post(url, async (error, response, body) => {
      // Parse response to JSON
      if (error) {
        console.log("Cannot refresh access_token: ", error);
        reject(error);
      }
      try {
        body = JSON.parse(body);

        // Logs your access and refresh tokens in the browser
        console.log(`access_token: ${body.access_token}`);
        console.log(`refresh_token: ${body.refresh_token}`);
        //TODO(erajain): Get item from DB table using email and update refresh_token to body.refresh_token
        let fetch_url = "https://api.zoom.us/v2/past_meetings/" + meeting_id + "/participants"
        const fetchPromise = await fetch(fetch_url, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${body.access_token}`
          }
        });
        return fetchPromise;
      } catch (e) {
        console.log("Cannot parse the json: ", e)
        reject(e);
      }
    }).auth(process.env.clientID, process.env.clientSecret);
  }

  const port = process.env.PORT || 4000;
  app.listen(port, () => console.log(`DeepInsights Zoom App Server listening on port ${port}!`));
}