// BookBeacon — Stripe webhook handler
//
// Listens for `checkout.session.completed` events from Stripe and marks the
// matching BookBeacon user as paid in Supabase. Written with zero npm
// dependencies (only Node's built-in `crypto` + global `fetch`) so it can be
// deployed with this plugin's site — including plain drag-and-drop deploys
// that don't run `npm install`.
//
// Required environment variables (set these in Netlify: Site settings →
// Environment variables):
//   STRIPE_WEBHOOK_SECRET     — from Stripe Dashboard → Developers → Webhooks
//                                → your endpoint → "Signing secret" (starts whsec_)
//   SUPABASE_URL              — https://nlhgswqvsnporitagaoq.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY — Supabase Project Settings → API → service_role
//                                key. SECRET — never put this in the app's
//                                front-end code, only here as a server env var.

import crypto from 'node:crypto';

function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!sigHeader) return false;
  const parts = Object.fromEntries(
    sigHeader.split(',').map(pair => {
      const idx = pair.indexOf('=');
      return [pair.slice(0, idx), pair.slice(idx + 1)];
    })
  );
  const timestamp = parts['t'];
  const expectedSig = parts['v1'];
  if (!timestamp || !expectedSig) return false;

  const signedPayload = `${timestamp}.${rawBody}`;
  const computed = crypto.createHmac('sha256', secret).update(signedPayload, 'utf8').digest('hex');

  try {
    return crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(expectedSig, 'hex'));
  } catch {
    return false;
  }
}

export default async (req) => {
  const sigHeader = req.headers.get('stripe-signature');
  const rawBody = await req.text();

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) {
    console.error('STRIPE_WEBHOOK_SECRET is not set');
    return new Response('Server not configured', { status: 500 });
  }

  if (!verifyStripeSignature(rawBody, sigHeader, webhookSecret)) {
    return new Response('Invalid signature', { status: 400 });
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return new Response('Bad JSON', { status: 400 });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.client_reference_id;

    if (userId) {
      const supabaseUrl = process.env.SUPABASE_URL;
      const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

      const resp = await fetch(`${supabaseUrl}/rest/v1/profiles?user_id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        headers: {
          apikey: serviceKey,
          Authorization: `Bearer ${serviceKey}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({
          paid: true,
          stripe_customer_id: session.customer || null,
          stripe_checkout_session_id: session.id,
          updated_at: new Date().toISOString(),
        }),
      });

      if (!resp.ok) {
        const errText = await resp.text();
        console.error('Failed to mark user paid in Supabase:', resp.status, errText);
        return new Response('Failed to update profile', { status: 500 });
      }
    } else {
      console.warn('checkout.session.completed with no client_reference_id — cannot match to a user');
    }
  }

  return new Response('ok', { status: 200 });
};
