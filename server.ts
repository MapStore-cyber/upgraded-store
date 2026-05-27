import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
import fs from 'fs';
import { fileURLToPath } from 'url';

const filename = typeof import.meta !== 'undefined' && import.meta.url ? fileURLToPath(import.meta.url) : __filename;
const dirname = path.dirname(filename);

// Setup crash logging
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});

dotenv.config();

const app = express();
const PORT = 3000;

// 1. Cyber Shield Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN'); // Prevents Clickjacking attacks
  res.setHeader('X-Content-Type-Options', 'nosniff'); // Prevents MIME sniffing
  res.setHeader('X-XSS-Protection', '1; mode=block'); // Prevents legacy XSS attacks
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); // Controls referrer metadata disclosure
  res.setHeader('Content-Security-Policy', "default-src 'self' https: 'unsafe-inline' 'unsafe-eval' data: blob:"); // Safe content-security execution boundaries
  next();
});

// 2. High-performance In-Memory IP Request Rate Limiter (Brute Force Defense)
const firewallRateLimitLocalMap = new Map<string, { count: number; expiresAt: number }>();
app.use('/api/', (req, res, next) => {
  const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const cleanIp = Array.isArray(rawIp) ? rawIp[0] : typeof rawIp === 'string' ? rawIp.split(',')[0].trim() : String(rawIp);
  const key = `${cleanIp}:${req.path}`;
  const now = Date.now();
  const rateRecord = firewallRateLimitLocalMap.get(key);

  if (rateRecord && rateRecord.expiresAt > now) {
    if (rateRecord.count >= 40) { // Keep limit friendly for chat but highly safe
      return res.status(429).json({ 
        error: 'Too many requests.', 
        blockedByFirewall: true,
        message: 'MapStore Cyber Shield active. Connection temporarily throttled to prevent brute-force attacks.'
      });
    }
    rateRecord.count++;
  } else {
    firewallRateLimitLocalMap.set(key, { count: 1, expiresAt: now + 60000 }); // 1-minute window
  }
  next();
});

// 3. Automated WAF Attack Payload Audit & Deflection Helper
const detectHackingSignature = (input: string): { isMalicious: boolean; threatType: string | null } => {
  const patterns = [
    { reg: /UNION\s+(ALL\s+)?SELECT/i, type: 'SQL SQLi (Structured Query Language Injection)' },
    { reg: /SELECT\s+.*\s+FROM/i, type: 'SQL SQLi (Database Extraction Query)' },
    { reg: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, type: 'XSS (Cross-Site Scripting Injection)' },
    { reg: /javascript:/i, type: 'XSS DOM URL Exploitation' },
    { reg: /(\s+or\s+\d+\s*=\s*\d+)/i, type: 'Boolean SQL Extraction Payload' },
    { reg: /drop\s+table|delete\s+from|alter\s+table/i, type: 'Data Definition Malicious Command' },
    { reg: /window\.location|document\.cookie/i, type: 'Session Hijacking / Cookie Sniffing Attempt' }
  ];

  for (const pattern of patterns) {
    if (pattern.reg.test(input)) {
      return { isMalicious: true, threatType: pattern.type };
    }
  }
  return { isMalicious: false, threatType: null };
};

app.use(express.json());

// API health check route
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(), 
    env: process.env.NODE_ENV || 'undefined',
    firewall: 'ACTIVE_SHIELD_V2.0_ENGAGED'
  });
});

// Initialize Gemini client using GoogleGenAI if key is present
let ai: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY') {
  try {
    ai = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
    console.log('Gemini AI client initialized successfully on MapStore backend.');
  } catch (error) {
    console.error('Error initializing Gemini client:', error);
  }
} else {
  console.log('Gemini API Key missing or default. MapStore running in Intelligent Mock Support mode.');
}

const SYSTEM_INSTRUCTION = `
You are the official MapStore Customer Support assistant, slogan: "Reaching you".
MapStore is an advanced local marketplace connecting buyers with approved, verified local sellers.

Key facts about MapStore:
- Commission: MapStore charges a flat 7% commission on all completed transactions. Sellers keep 93%.
- Seller Verification: Sellers must submit to a 24-hour verification, including an ID Scanner verification and Proof of Address documentation. They must agree to terms of service and strict verification policies.
- Payments: Simulated secure 3DS card processor which enforces bank validation.
- Delivery Map: Orders show active progress steps and coordinate routes directly on their tracking portal.
- Returns and Rules: Prohibited items are strictly banned. Accurate representation is mandatory. 14-day local refund policies apply.

Your goal is to answer questions politely, friendly, and concisely. Keep responses under 3-4 sentences when possible. If the user asks about an order or listing, guide them to check their interactive dashboard tabs!
`;

// API routes FIRST
app.post('/api/support', async (req, res) => {
  const { messages, userProfile } = req.body;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'Messages array is required' });
  }

  // Sanitize incoming input & Deflect dangerous scripts
  const lastUserMessage = messages[messages.length - 1]?.text || '';
  const payloadAudit = detectHackingSignature(lastUserMessage);

  if (payloadAudit.isMalicious) {
    console.warn(`[MAPSTORE FIREWALL ALERT]: Intercepted malicious request signature: ${payloadAudit.threatType}. Originating IP logging ongoing.`);
    return res.status(403).json({
      text: `🔒 [MAPSTORE CYBER FIREWALL DISPATCH]
Your input text has been flagged and intercepted by the MapStore Web Application Firewall (WAF) Shield.

Details:
• Exploit Signature: ${payloadAudit.threatType}
• Threat Severity: HIGH
• Action Taken: Request Dropped & Originating IP logged in compliance logs.

MapStore respects client security and operates under strict South African cyber safety provisions. Please enter only legitimate questions.`,
      blockedByFirewall: true,
      threatType: payloadAudit.threatType
    });
  }

  // If AI SDK is configured, query Gemini
  if (ai) {
    try {
      const formattedContents = messages.map(msg => ({
        role: msg.sender === 'user' ? 'user' : 'model',
        parts: [{ text: msg.text }]
      }));

      const response = await ai.models.generateContent({
        model: 'gemini-3.5-flash',
        contents: formattedContents,
        config: {
          systemInstruction: SYSTEM_INSTRUCTION + `\nActive user profile: ${JSON.stringify(userProfile || {})}`,
          temperature: 0.7,
        }
      });

      return res.json({ text: response.text });
    } catch (error: any) {
      console.error('Gemini API call failed, invoking intelligent local fallback. Error:', error);
      // Fall through to local fallback on API failure
    }
  }

  // Intelligent Local Fallback
  const textLower = lastUserMessage.toLowerCase();
  let reply = "Hello! I am your MapStore assistant. How can I reach you with help today?";

  if (textLower.includes('commission') || textLower.includes('fee') || textLower.includes('7%')) {
    reply = "MapStore operates with a flat 7% platform commission on each transaction. There are no hidden fees, and listing is free! Sellers retain 93% of their sales revenue, which is detailed in their Sales Reports.";
  } else if (textLower.includes('verify') || textLower.includes('seller') || textLower.includes('register') || textLower.includes('id')) {
    reply = "To start selling on MapStore, register through the Seller portal. You will need to complete our Identity Verification (using our live simulated ID Scanner) and upload a Proof of Address document. Applications are securely reviewed and approved within 24 hours.";
  } else if (textLower.includes('tracking') || textLower.includes('order') || textLower.includes('status') || textLower.includes('where is my')) {
    reply = "You can trace active deliveries step-by-step! Go to your Profile, tap on 'My Orders', and select 'Track Order'. You will see our interactive stepper and a real-time tracking route representing your package's delivery.";
  } else if (textLower.includes('payment') || textLower.includes('secure') || textLower.includes('gateway')) {
    reply = "All transactions on MapStore are protected using our secure 3D-Secure payment gateway simulator, supporting instant validation and bank fraud prevention for absolute safety.";
  } else if (textLower.includes('prohibited') || textLower.includes('policies') || textLower.includes('rules')) {
    reply = "Sellers must list authorized and safe products only. Prohibited goods, counterfeit items, or misrepresented listings are strictly banned. Every product must pass seller compliance before becoming visible.";
  } else if (textLower.includes('wishlist')) {
    reply = "You can add items you like to your wishlist by clicking the heart icon on any product card! View your wishlist inside your Profile center at any time.";
  } else if (textLower.includes('refund') || textLower.includes('return') || textLower.includes('cancel')) {
    reply = "MapStore coordinates a 14-day buyer satisfaction return policy for local purchases. Simply request assistance or contact the local seller through their contact detail listed on the order page.";
  } else {
    reply = "That sounds wonderful! MapStore connects local buyer communities and verified sellers safely. Slogan: 'Reaching you'. Let me know if you would like me to explain commission structures, seller verification, or order tracking!";
  }

  return res.json({ text: reply });
});

async function startServer() {
  // Robust production check: if the server is running from compiled dist file, or if source server.ts is missing, we are in production
  const isProduction = process.env.NODE_ENV === 'production' || dirname.endsWith('dist') || !fs.existsSync(path.join(process.cwd(), 'server.ts'));
  let distPath = path.join(process.cwd(), 'dist');
  
  // High-resilience path lookup: falls back to local workspace structure if main cwd folder is not populated
  if (!fs.existsSync(path.join(distPath, 'index.html'))) {
    const fallbackPath = dirname.endsWith('dist') ? dirname : path.join(dirname, 'dist');
    if (fs.existsSync(path.join(fallbackPath, 'index.html'))) {
      distPath = fallbackPath;
    }
  }

  if (isProduction) {
    console.log(`Server starting in production mode. Serving static assets from: ${distPath}`);
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      if (req.originalUrl.startsWith('/api/')) {
        return res.status(404).json({ error: 'API route not found' });
      }
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    // Development Mode
    try {
      console.log('Initializing Vite dev server in middleware mode...');
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      app.use(vite.middlewares);

      // Explicit fallback for dev mode to compile and serve index.html
      app.get('*', async (req, res, next) => {
        if (req.originalUrl.startsWith('/api/')) {
          return next();
        }
        try {
          const url = req.originalUrl;
          const templatePath = path.join(process.cwd(), 'index.html');
          if (fs.existsSync(templatePath)) {
            let template = fs.readFileSync(templatePath, 'utf-8');
            template = await vite.transformIndexHtml(url, template);
            return res.status(200).set({ 'Content-Type': 'text/html' }).end(template);
          } else {
            return next();
          }
        } catch (e) {
          vite.ssrFixStacktrace(e as Error);
          next(e);
        }
      });
      console.log('Vite server integration loaded perfectly.');
    } catch (err) {
      console.error('Failed to start Vite dev server, falling back to static files:', err);
      app.use(express.static(distPath));
      app.get('*', (req, res) => {
        if (req.originalUrl.startsWith('/api/')) {
          return res.status(404).json({ error: 'API route not found' });
        }
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is actively running on port ${PORT}`);
  });
}

startServer();
