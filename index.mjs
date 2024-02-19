import OAuth from 'oauth-1.0a';
import crypto from 'crypto';
import AWS from 'aws-sdk';
import request from 'request-promise';
import jwt from 'jsonwebtoken';

// Initialize AWS DynamoDB DocumentClient
const dynamo_db = new AWS.DynamoDB.DocumentClient();
const table_partners = 'partner_connections';
const table_parters_user_ids = 'partner_user_ids';

// Initialize the OAuth object outside of the handler to make it globally accessible
const oauth = OAuth({
    consumer: {
        key: '72d9de28-9936-4fe8-9cd6-52f4b5e4fbdd',
        secret: 'VYSqkvdwyhMZxVJwzjb17sBOZPz6CAAnffe'
    },
    signature_method: 'HMAC-SHA1',
    hash_function(base_string, key) {
        return crypto.createHmac('sha1', key).update(base_string).digest('base64');
    }
});

export async function handler(event) {
    console.log("Received event:", JSON.stringify(event));

    const { oauth_verifier, oauth_token } = JSON.parse(event.body);
    console.log('Received oauth_verifier:', oauth_verifier);
    console.log('Received oauth_token:', oauth_token);

    const jwt_token = event.headers.Authorization || event.headers.authorization;
    const decoded_jwt = jwt.decode(jwt_token);
    const user_id = decoded_jwt.sub;
    console.log("Decoded JWT user ID:", user_id);

    let oauth_token_secret;
    try {
        const { Item } = await dynamo_db.get({
            TableName: table_partners,
            Key: {
                user_id: user_id,
                partner: 'garmin'
            }
        }).promise();
    
        if (!Item || !Item.partner_temp_token_secret) {
            throw new Error("OAuth token secret not found for user");
        }
    
        oauth_token_secret = Item.partner_temp_token_secret;
        console.log("Retrieved oauth_token_secret:", oauth_token_secret);
    } catch (error) {
        console.error("Error retrieving oauth_token_secret from DynamoDB:", error);
        return {
            statusCode: 500,
            body: JSON.stringify({ message: "Failed to retrieve oauth_token_secret from DynamoDB" })
        };
    }

    const authorization = oauth.authorize({
        url: 'https://connectapi.garmin.com/oauth-service/oauth/access_token',
        method: 'POST',
        data: { oauth_verifier, oauth_token }
    }, { key: oauth_token, secret: oauth_token_secret });

    console.log('Authorization header:', oauth.toHeader(authorization).Authorization);

    try {
        const response_body = await request({
            url: 'https://connectapi.garmin.com/oauth-service/oauth/access_token',
            method: 'POST',
            headers: {
                'Authorization': oauth.toHeader(authorization).Authorization
            }
        });

        console.log("Garmin response:", response_body);

        const response_params = new URLSearchParams(response_body);
        const response_oauth_token = response_params.get('oauth_token');
        const response_oauth_token_secret = response_params.get('oauth_token_secret');

        console.log('Received response oauth_token:', response_oauth_token);
        console.log('Received response oauth_token_secret:', response_oauth_token_secret);

        const garmin_user_id = await fetch_user_id(response_oauth_token, response_oauth_token_secret);
        console.log('Garmin User ID:', garmin_user_id);

        await update_dynamo_db(user_id, response_oauth_token, response_oauth_token_secret, garmin_user_id);
        await request_backfill(response_oauth_token, response_oauth_token_secret);

        return {
            statusCode: 200,
            body: JSON.stringify({}),
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
                "Access-Control-Allow-Methods": "OPTIONS,POST"
            }
        };
    } catch (error) {
        console.error('Error:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({ message: 'Failed to retrieve tokens or user ID', error: error.message }),
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
                "Access-Control-Allow-Methods": "OPTIONS,POST"
            }
        };
    }
}

async function fetch_user_id(oauth_token, oauth_token_secret) {
    const user_data_request = {
        url: 'https://apis.garmin.com/wellness-api/rest/user/id',
        method: 'GET'
    };

    const user_authorization = oauth.authorize(user_data_request, {
        key: oauth_token,
        secret: oauth_token_secret
    });

    try {
        const response = await request({
            url: user_data_request.url,
            method: user_data_request.method,
            headers: {
                'Authorization': oauth.toHeader(user_authorization).Authorization
            },
            json: true
        });

        return response.userId;
    } catch (error) {
        console.error('Failed to fetch Garmin User ID:', error);
        throw error;
    }
}

async function update_dynamo_db(user_id, garmin_oauth_token, garmin_token_secret, garmin_user_id) {
    const partner_connections_params = {
        TableName: table_partners,
        Key: { user_id, partner: 'garmin' },
        UpdateExpression: 'set partner_user_id = :puid, partner_oauth_token = :pot, partner_token_secret = :pts',
        ExpressionAttributeValues: {
            ':puid': garmin_user_id,
            ':pot': garmin_oauth_token,
            ':pts': garmin_token_secret
        }
    };

    const partner_user_id_params = {
        TableName: table_parters_user_ids, // Replace with your actual table name
        Key: { 
            partner_user_id: garmin_user_id,
            partner: 'garmin' // Assuming this is the correct key and variable name
        },
        UpdateExpression: 'SET user_id = :uid',
        ExpressionAttributeValues: {
            ':uid': user_id,
        }
    };

    try {
        await Promise.all([
            dynamo_db.update(partner_connections_params).promise(),
            dynamo_db.update(partner_user_id_params).promise()
        ]);
        console.log('Tables updated successfully');
    } catch (error) {
        console.error('Error updating tables:', error);
        throw error;
    }
}

async function request_backfill(garmin_oauth_token, garmin_token_secret) {
    // Determine the current date
    const current_date = new Date();

    // Generate timestamps for the last three months in 2-week intervals
    const intervals = generate_intervals(current_date);

    for (const interval of intervals) {
        const { start_time, end_time } = interval;

        const request_data = {
            url: 'https://apis.garmin.com/wellness-api/rest/backfill/activities',
            method: 'GET',
            data: {
                summaryStartTimeInSeconds: start_time,
                summaryEndTimeInSeconds: end_time
            }
        };

        const token = {
            key: garmin_oauth_token,
            secret: garmin_token_secret
        };

        // Authorize and sign the request
        const authorization = oauth.authorize(request_data, token);

        try {
            // Make the request
            const response = await request({
                url: request_data.url + `?summaryStartTimeInSeconds=${start_time}&summaryEndTimeInSeconds=${end_time}`,
                method: request_data.method,
                headers: {
                    'Authorization': oauth.toHeader(authorization).Authorization
                }
            });

            console.log('Backfill request response:', response);

            // We don't need to do anything with the response since the backfill process is asynchronous
        } catch (error) {
            console.error('Failed to request backfill:', error);
            throw error;
        }
    }
}

function generate_intervals(current_date) {
    const intervals = [];
    const four_weeks_in_seconds = 4 * 7 * 24 * 60 * 60;
    let end_time = Math.floor(current_date.getTime() / 1000); // Current time in seconds
    let start_time = end_time - four_weeks_in_seconds; // one weeks ago in seconds

    // Generate intervals for the last three months
    for (let i = 0; i < 3; i++) { // 3 months / 2 weeks = 6 intervals + 2 extra weeks + 8 intervals
        intervals.push({ start_time, end_time });
        end_time = start_time; // Set the end of the next interval to the start of the current one
        start_time -= four_weeks_in_seconds; // Move the start back another two weeks
    }

    return intervals;
}