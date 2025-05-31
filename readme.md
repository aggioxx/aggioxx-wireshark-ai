# Basic Experimentation with LLM for Wireshark Packet Analysis
   
   ## Overview
   This project is an experimental demonstration of how a Large Language Model \(LLM\) can assist in analyzing network packets captured with Wireshark. It uses Python libraries and specialized models to summarize packet data and provide insights into potential anomalies.
   
   ## Requirements
   \- Python 3.8\+
   \- PyTorch
   \- Transformers
   \- Pyshark
   \- LangChain
   \- TikToken
   \- OpenAI API Key
   
   ## Getting Started
   1. Install dependencies:
      \```
      pip install -r requirements.txt
      \```
   2. Add your OpenAI API key to an \`.env\` file as \`OPENAI_API_KEY=YOUR_KEY\`.
   3. Run the Python scripts to capture packets, process summaries, or engage with the LLM-based chat interface.
   
   ## How It Works
   \- Network packets are parsed for IP, port, protocol, and other headers.
   \- An LLM or fine-tuned model processes packet data, generating embeddings or summaries.
   \- A question-answering pipeline provides real-time insights into network behavior.
   
   ## Contributing
   Feel free to fork and modify this project. Submit pull requests for any interesting enhancements.