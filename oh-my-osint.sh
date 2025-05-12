#!/bin/bash

# Get the full path to the streamlit executable
STREAMLIT_PATH=$(which streamlit)

# Check if streamlit is found
if [ -z "$STREAMLIT_PATH" ]; then
    echo "❌ Error: streamlit not found in your PATH."
    exit 1
fi

# Run the Streamlit app with sudo using the resolved path
echo "✅ Found streamlit at: $STREAMLIT_PATH"
echo "🚀 Launching OSINT app with elevated privileges..."
sudo "$STREAMLIT_PATH" run oh-my-osint.py
