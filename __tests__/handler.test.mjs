import AWS from 'aws-sdk';
import request from 'request-promise';
import jwt from 'jsonwebtoken';

import { handler } from '../index.mjs';

jest.mock('aws-sdk', () => ({
  DynamoDB: {
    DocumentClient: jest.fn(() => ({
      get: jest.fn().mockImplementation(() => ({
        promise: jest.fn().mockResolvedValue({
          Item: { partner_temp_token_secret: 'oauth_token_secret' }
        })
      })),
      update: jest.fn().mockImplementation(() => ({
        promise: jest.fn().mockResolvedValue({})
      }))
    }))
  }
}));

jest.mock('request-promise', () => jest.fn().mockImplementation((options) => {
    if (options.url.includes('oauth/access_token')) {
      return Promise.resolve('oauth_token=new_token&oauth_token_secret=new_secret');
    } else if (options.url.includes('user/id')) {
      // Ensure JSON string response to mimic actual HTTP response behavior
      return Promise.resolve(JSON.stringify({ userId: 'garmin_user_id' }));
    } else {
      return Promise.resolve('backfill_success');
    }
  }));
  

jest.mock('jsonwebtoken', () => ({
  decode: jest.fn().mockReturnValue({ sub: 'decoded_user_id' })
}));

const mockedDocumentClient = AWS.DynamoDB.DocumentClient;

describe('OAuth Handler Function Tests', () => {

    it('successfully handles valid OAuth flow', async () => {
        // Define the event object inside the test case to ensure it's in the correct scope
        const event = {
            'body-json': { oauth_verifier: 'verifier', oauth_token: 'token' },
            params: { header: { Authorization: 'Bearer jwtToken' } }
        };

        // Call the handler with the event
        const response = await handler(event);

        expect(response.statusCode).toEqual(200);
        // validate get
        expect(AWS.DynamoDB.DocumentClient.mock.results[0].value.get).toHaveBeenCalledWith({
            TableName: 'partner_connections',
            Key: {
                user_id: 'decoded_user_id', 
                partner: 'garmin'
            }
        });
        // validate update
        expect(AWS.DynamoDB.DocumentClient.mock.results[0].value.update.mock.calls[0][0]).toMatchObject({
            TableName: 'partner_connections',
            Key: { user_id: 'decoded_user_id', partner: 'garmin' },
        });
        // validate request
        expect(request.mock.calls[0][0]).toEqual({
            url: 'https://connectapi.garmin.com/oauth-service/oauth/access_token',
            method: 'POST',
            headers: {
                'Authorization': expect.stringContaining('OAuth') 
            }
        });
        // validate jwt
        expect(jwt.decode).toHaveBeenCalledWith('Bearer jwtToken');        
    });
    it('handles failure in OAuth token exchange', async () => {
        // Mock request-promise to simulate a failed OAuth token exchange
        request.mockImplementationOnce((options) => {
            if (options.url.includes('oauth/access_token')) {
                return Promise.reject(new Error('OAuth exchange error'));
            }
            // Fallback to original mock behavior for other URLs
            return Promise.resolve('fallback_success_response');
        });

        // Define the event object
        const event = {
            'body-json': { oauth_verifier: 'verifier', oauth_token: 'token' },
            params: { header: { Authorization: 'Bearer jwtToken' } }
        };

        const response = await handler(event);

        expect(response.statusCode).toEqual(500);
        // Validate the error message in the response
        expect(JSON.parse(response.body).message).toContain('Failed to retrieve tokens');
        
        // Assert that jwt.decode was called with the correct token
        expect(jwt.decode).toHaveBeenCalledWith('Bearer jwtToken');
    });
});

