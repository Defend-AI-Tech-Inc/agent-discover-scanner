/**
 * Test fixture: Unmanaged OpenAI in JavaScript
 * Should trigger: DAI004 - error
 */
import OpenAI from 'openai';

// Direct OpenAI usage - Shadow AI
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const completion = await client.chat.completions.create({
  model: "gpt-4",
  messages: [{ role: "user", content: "Hello" }],
});
