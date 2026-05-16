import os
import shutil
from pathlib import Path
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURATION ---
DB_NAME = "./vector_db"
KNOWLEDGE_BASE = "./knowledge-base"
# Ensure your .env has the API key
embeddings = OpenAIEmbeddings(model="text-embedding-3-large")

def build_vector_store():
    # 1. THE "CLEAN SLATE" LOGIC
    if os.path.exists(DB_NAME):
        print(f"🧹 Removing existing database at {DB_NAME}...")
        try:
            shutil.rmtree(DB_NAME)
            print("✅ Old database cleared.")
        except Exception as e:
            print(f"❌ Error clearing database: {e}")
            return

    # 2. LOAD DOCUMENTS
    print(f"📥 Loading files from {KNOWLEDGE_BASE}...")
    if not os.path.exists(KNOWLEDGE_BASE):
        print(f"❌ Error: {KNOWLEDGE_BASE} folder not found!")
        return

    loader = DirectoryLoader(
        KNOWLEDGE_BASE, glob="**/*.md", loader_cls=TextLoader
    )
    docs = loader.load()
    
    if not docs:
        print("⚠️ No markdown files found in the knowledge base.")
        return

    # 3. SPLIT TEXT
    # Security docs are dense; smaller chunks are better for precision
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=600, 
        chunk_overlap=100
    )
    splits = text_splitter.split_documents(docs)

    # 4. CREATE VECTOR STORE
    print(f"🧠 Indexing {len(splits)} chunks into ChromaDB...")
    vectorstore = Chroma.from_documents(
        documents=splits, 
        embedding=embeddings, 
        persist_directory=DB_NAME
    )
    
    print(f"✨ Knowledge Base Sync Complete. System is now online.")
    return vectorstore

if __name__ == "__main__":
    build_vector_store()
