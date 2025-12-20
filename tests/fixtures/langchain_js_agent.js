/**
 * Test fixture: LangChain.js agent
 * Should trigger: DAI003 - warning
 */
import { ChatOpenAI } from "@langchain/openai";
import { AgentExecutor, createReactAgent } from "langchain/agents";

const model = new ChatOpenAI({
  temperature: 0,
});

// This should be detected
const agent = await createReactAgent({
  llm: model,
  tools: [],
});

const agentExecutor = new AgentExecutor({
  agent,
  tools: [],
});
