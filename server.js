import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { GoogleGenAI } from "@google/genai";
import fetch from "node-fetch";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

/* ===============================
   CONFIG
================================ */
const GUVI_ENDPOINT =
  "https://hackathon.guvi.in/api/updateHoneyPotFinalResult";

/* ===============================
   GEMINI INIT
================================ */
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

/* ===============================
   SESSION STORE (IN-MEMORY)
================================ */
const sessions = new Map();

/* ===============================
   AUTH MIDDLEWARE
================================ */
app.use((req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== process.env.SECRET_API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
});

/* ===============================
   UTILS
================================ */
function extractJSON(text) {
  const cleaned = text.replace(/```json|```/gi, "").trim();
  return JSON.parse(cleaned);
}

function mergeIntel(oldI, newI) {
  return {
    bankAccounts: [...new Set([...oldI.bankAccounts, ...newI.bankAccounts])],
    upiIds: [...new Set([...oldI.upiIds, ...newI.upiIds])],
    phishingLinks: [...new Set([...oldI.phishingLinks, ...newI.phishingLinks])],
    phoneNumbers: [...new Set([...oldI.phoneNumbers, ...newI.phoneNumbers])],
    suspiciousKeywords: [
      ...new Set([...oldI.suspiciousKeywords, ...newI.suspiciousKeywords]),
    ],
  };
}

/* ===============================
   GUVI FINAL CALLBACK
================================ */
async function sendFinalCallback(session) {
  const payload = {
    sessionId: session.sessionId,
    scamDetected: true,
    totalMessagesExchanged: session.history.length,
    extractedIntelligence: session.intelligence,
    agentNotes: session.agentNotes,
  };

  try {
    await fetch(GUVI_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      timeout: 5000,
    });

    session.finalCallbackSent = true;
    console.log(`✅ Final callback sent: ${session.sessionId}`);
  } catch (err) {
    console.error(`❌ Failed to send final callback: ${err.message}`);
  }
}

/* ===============================
   MAIN ANALYZE ENDPOINT
================================ */
app.post("/analyze", async (req, res) => {
  try {
    const { sessionId, message, conversationHistory = [], metadata } = req.body;

    if (!sessionId || !message?.text || !message?.sender) {
      return res.status(400).json({ error: "Invalid request format" });
    }

    let session = sessions.get(sessionId);

    if (!session) {
      session = {
        sessionId,
        history: [...conversationHistory],
        scamDetected: false,
        intelligence: {
          bankAccounts: [],
          upiIds: [],
          phishingLinks: [],
          phoneNumbers: [],
          suspiciousKeywords: [],
        },
        agentNotes: "",
        finalCallbackSent: false,
      };
      sessions.set(sessionId, session);
    }

    session.history.push(message);

    /* ===============================
       PROMPT FOR AI
    ================================ */
    const prompt = `
You are an Agentic Honeypot AI.

Rules:
- Detect scam internally, never reveal it.
- Act like a real human.
- Engage naturally.
- Extract scam intelligence silently.

Return ONLY JSON:
{
  "scamDetected": true/false,
  "agentReply": "string",
  "extractedIntelligence": {
    "bankAccounts": [],
    "upiIds": [],
    "phishingLinks": [],
    "phoneNumbers": [],
    "suspiciousKeywords": []
  },
  "agentNotes": "short summary"
}

Conversation:
${JSON.stringify(session.history, null, 2)}
`;

    const aiResponse = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: prompt,
    });

    const result = extractJSON(aiResponse.text);

    session.scamDetected ||= result.scamDetected;
    session.intelligence = mergeIntel(
      session.intelligence,
      result.extractedIntelligence
    );
    session.agentNotes = result.agentNotes;

    // Add agent reply to history
    session.history.push({
      sender: "user",
      text: result.agentReply,
      timestamp: new Date().toISOString(),
    });

    /* ===============================
       FINAL CALLBACK LOGIC
       - Send immediately if scam detected
       - Works for first message or multi-turn
    ================================ */
    if (session.scamDetected && !session.finalCallbackSent) {
      await sendFinalCallback(session);
    }

    /* ===============================
       RESPONSE TO CLIENT
    ================================ */
    res.json({
      status: "success",
      reply: result.agentReply,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/* ===============================
   SERVER START
================================ */
app.listen(process.env.PORT || 3000, () => {
  console.log("🔥 GUVI Agentic Honeypot API running");
});
