#!/bin/bash

# =====================================================================
# Styreportalen Codebase Setup Script
# =====================================================================
# This script sets up the directory structure and creates placeholder
# files for the Styreportalen project, including Backend (ASP.NET Core)
# and Frontend (React) components.
# =====================================================================

# Base Directory
BASE_DIR=$(pwd)

# Function to create directories and files
create_structure() {
  echo "Setting up the Styreportalen codebase..."

  # Create Backend Directory Structure
  mkdir -p Backend/Controllers
  mkdir -p Backend/Models
  mkdir -p Backend/Data
  mkdir -p Backend/Services
  mkdir -p Backend/Filters
  mkdir -p Backend/Migrations
  mkdir -p Backend/Properties

  # Create Frontend Directory Structure
  mkdir -p frontend/src/components
  mkdir -p frontend/src/pages
  mkdir -p frontend/src/utils
  mkdir -p frontend/public
  mkdir -p frontend/src/styles

  # Create Root-Level Files
  touch Backend/appsettings.json
  touch Backend/Program.cs
  touch frontend/package.json
  touch frontend/.env
  touch frontend/src/index.js
  touch frontend/src/App.js
  touch frontend/src/reportWebVitals.js
  touch frontend/src/setupTests.js

  # Create Placeholder Controllers
  touch Backend/Controllers/DocumentsController.cs
  touch Backend/Controllers/HighlightsController.cs
  touch Backend/Controllers/MessagesController.cs
  touch Backend/Controllers/AuthController.cs

  # Create Placeholder Models
  touch Backend/Models/Document.cs
  touch Backend/Models/DocumentVersion.cs
  touch Backend/Models/Highlight.cs
  touch Backend/Models/Message.cs
  touch Backend/Models/SendMessageModel.cs
  touch Backend/Models/RevertVersionModel.cs
  touch Backend/Models/DocumentUploadModel.cs
  touch Backend/Models/HighlightModel.cs

  # Create ApplicationDbContext
  touch Backend/Data/ApplicationDbContext.cs

  # Create Placeholder Services
  touch Backend/Services/IEncryptionService.cs
  touch Backend/Services/EncryptionService.cs
  touch Backend/Services/MeetingReminderService.cs
  touch Backend/Services/IEmailSender.cs
  touch Backend/Services/EmailSender.cs

  # Create Placeholder Filters
  touch Backend/Filters/MfaRequiredAttribute.cs
  touch Backend/Filters/HangfireAuthorizationFilter.cs

  # Create Frontend Components
  touch frontend/src/components/AnnotateDocument.js
  touch frontend/src/components/CommitteeMessages.js

  # Create Frontend Pages
  touch frontend/src/pages/Documents.js
  touch frontend/src/pages/Meetings.js
  touch frontend/src/pages/CommitteeDetails.js

  # Create Frontend Utilities
  touch frontend/src/utils/axios.js

  echo "Directory structure and placeholder files created successfully."
}

# Function to initialize Backend (ASP.NET Core) Project
initialize_backend() {
  echo "Initializing Backend (ASP.NET Core) project..."

  cd Backend

  # Initialize a new ASP.NET Core Web API project
  dotnet new webapi --no-https --output . --framework net6.0

  # Remove default Controllers
  rm Controllers/WeatherForecastController.cs
  rm WeatherForecast.cs

  echo "Backend project initialized."
  cd ..
}

# Function to initialize Frontend (React) Project
initialize_frontend() {
  echo "Initializing Frontend (React) project..."

  cd frontend

  # Initialize a new React app using Create React App
  npx create-react-app . --template cra-template-pwa

  # Install necessary dependencies
  npm install @mui/material @mui/icons-material react-router-dom axios react-pdf react-pdf-highlighter

  echo "Frontend project initialized."
  cd ..
}

# Execute Functions
create_structure
initialize_backend
initialize_frontend

echo "Styreportalen codebase setup completed successfully."