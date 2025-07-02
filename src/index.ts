import {
  ClientConfig,
  MessageAPIResponseBase,
  messagingApi,
  webhook,
  HTTPFetchError,
} from '@line/bot-sdk';
import { Buffer } from 'node:buffer';

export interface Env {
  CHANNEL_ACCESS_TOKEN: string;
  CHANNEL_SECRET: string;
}

const textEncoder = new TextEncoder();

// Existing signature validation for Cloudflare Workers
async function validateSignature(
  body: string,
  channelSecret: string,
  signature: string
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(channelSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signed = await crypto.subtle.sign('HMAC', key, textEncoder.encode(body));
  const base64 = Buffer.from(signed).toString('base64');
  return base64 === signature;
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    console.log(`Received request: ${request.method} ${request.url}`);

    // Handle GET requests for webhook verification
    if (request.method === 'GET') {
      return new Response('OK', { status: 200 });
    }

    // Only allow POST requests for webhook events
    if (request.method !== 'POST') {
      console.log(`Method Not Allowed: ${request.method}`);
      return new Response('Method Not Allowed', { status: 405 });
    }

    try {
      const signature = request.headers.get('x-line-signature');
      console.log(`X-Line-Signature: ${signature}`);

      if (!signature) {
        console.error('Bad Request: Missing signature');
        return new Response('Bad Request: Missing signature', { status: 400 });
      }

      const body = await request.text();
      console.log(`Request body: ${body}`);

      const isValid = await validateSignature(body, env.CHANNEL_SECRET, signature);
      if (!isValid) {
        console.error('Unauthorized: Invalid signature');
        return new Response('Unauthorized: Invalid signature', { status: 401 });
      }

      // Create a new LINE SDK client using messagingApi.MessagingApiClient
      const client = new messagingApi.MessagingApiClient({
        channelAccessToken: env.CHANNEL_ACCESS_TOKEN,
      });

      const callbackRequest: webhook.CallbackRequest = JSON.parse(body);
      const events: webhook.Event[] = callbackRequest.events!;
      console.log(`Parsed events: ${JSON.stringify(events)}`);

      // Process all the received events asynchronously.
      const results = await Promise.all(
        events.map(async (event: webhook.Event) => {
          try {
            // Adapt textEventHandler logic
            if (event.type !== 'message' || event.message.type !== 'text') {
              console.log(`Skipping non-text message or non-message event: ${event.type}`);
              return;
            }

            if (!event.replyToken) {
              console.log('No reply token found for event.');
              return;
            }

            console.log(`Replying to message: ${event.message.text}`);
            await client.replyMessage({
              replyToken: event.replyToken,
              messages: [{
                type: 'text',
                text: event.message.text,
              }],
            });
          } catch (err: unknown) {
            if (err instanceof HTTPFetchError) {
              console.error(`HTTPFetchError: Status ${err.status}, Request ID: ${err.headers.get('x-line-request-id')}, Body: ${err.body}`);
            } else if (err instanceof Error) {
              console.error(`Error processing event: ${err.message}`);
              console.error(err.stack);
            }
            throw err; // Re-throw to be caught by the outer try-catch
          }
        })
      );

      console.log('Successfully processed events.');
      return new Response('OK');
    } catch (error: any) {
      console.error(`Error processing request: ${error.message}`);
      console.error(error.stack);
      return new Response(`Internal Server Error: ${error.message}`, { status: 500 });
    }
  },
} satisfies ExportedHandler<Env>;