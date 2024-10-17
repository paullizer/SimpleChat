# Simple Chat Application - README

## Overview

The **Simple Chat Application** is designed to enable users to interact with a generative AI model via a web-based chat interface. The application supports Retrieval-Augmented Generation (RAG), allowing users to upload documents and perform hybrid searches against them, enhancing the quality of responses by combining AI knowledge with custom user data. The application runs on **Azure App Service**, specifically designed to work in **Azure Government**, but it also functions in **Azure Commercial** environments.

## Features

- **Chat with AI**: Interact with an AI model based on OpenAI's GPT.
- **RAG with Hybrid Search**: Upload documents and perform hybrid searches, retrieving relevant information from your files.
- **Document Management**: Upload, store, and manage multiple versions of documents.
- **Azure Cosmos DB**: Stores conversations and document metadata.
- **Azure Cognitive Search**: Facilitates efficient search and retrieval of document data.
- **Azure Document Intelligence**: Extracts data from various document formats, including PDFs, Word documents, and images.
- **Authentication**: Secured via Azure Active Directory (AAD) integration using MSAL (Microsoft Authentication Library).

## Folder Structure

```
📁 SimpleChat
├── 📁 artifacts
│   └── user-index.json
├── 📁 static
│   └── 📁 bootstrap
├── 📁 templates
│   └── base.html
│   └── chat.html
│   └── chats.html
│   └── conversations.html
│   └── documents.html
│   └── index.html
│   └── profile.html
├── app.py
├── requirements.txt
```

- **artifacts/**: Contains data files like indexes for user-specific searches.
- **static/**: Houses static assets such as CSS and Bootstrap files.
- **templates/**: HTML templates for rendering web pages, such as chat, document management, and user profile views.
- **app.py**: The main application logic, handling routing, authentication, chat, and file uploads.
- **requirements.txt**: Lists the Python dependencies required to run the app.

## Technology Stack

- **Flask**: Web framework for handling requests and rendering web pages.
- **Azure OpenAI**: Used for generating AI responses and creating document embeddings for RAG.
- **Azure Cosmos DB**: For storing conversations, documents, and metadata.
- **Azure Cognitive Search**: Enables document retrieval based on AI-embedded vectors.
- **Azure Document Intelligence**: Extracts text from uploaded documents in various formats.
- **MSAL**: Handles authentication with Azure Active Directory (AAD).

## Setup Instructions

### Prerequisites

- **Azure Subscription**: An active Azure subscription with Azure OpenAI, Cosmos DB, and Cognitive Search services enabled.
- **Azure App Service**: The application is deployed on Azure App Service. Ensure the service is available in your Azure environment.

### Initializing an Index in Azure AI Search Using the Azure Portal

The **Simple Chat Application** utilizes Azure AI Search for document retrieval. The `user-index.json` file contains the schema for creating the search index that will store user documents and metadata. Here's how to initialize the Azure AI Search index directly through the Azure portal using the `user-index.json` file.

#### Steps to Initialize the Index in the Azure Portal

1. **Access the Azure Portal**:
   - Go to the [Azure Portal](https://portal.azure.com/).
   - In the search bar at the top, search for **"Azure Cognitive Search"** and select your Azure AI Search resource.

2. **Navigate to Indexes**:
   - In the left-hand menu, select **Indexes** under the **Search Management** section.
   - Click on **+ Add Index from JSON**  to create a new index.

3. **Create Index from `user-index.json`**:
   - In the **Add Index from JSON** screen, you'll need to manually enter the index schema. Open the `user-index.json` file from the `artifacts/` folder in your project to view the schema, which includes fields, types, and configurations.
   
     ```
     📁 SimpleChat
     └── 📁 artifacts
         └── user-index.json
     ```
   
4. **Copy and Paste from `user-index.json` file into the open menu on the right** 

7. **Verify Index Creation**:
   - After the index is created, go back to the **Indexes** section in Azure AI Search.
   - You should now see the new index listed (e.g., `simplechat-user-index`).
   - Click on the index to verify that all the fields are set up correctly.

### Setting Up Authentication for the Simple Chat Application

To secure access to the **Simple Chat Application**, we configure authentication using **Azure Active Directory (Azure AD)**. The app is registered in **Microsoft Entra ID** (formerly Azure AD) to allow users to log in using their organizational credentials. Below are the steps for setting up authentication in **Azure App Service** and configuring the **Azure AD App Registration** for the application.

#### 1. **Enable Authentication in Azure App Service**

Authentication is enabled directly in the **Azure App Service** that hosts the application, ensuring that only authenticated users can access the app.

##### Steps to Enable Authentication:
1. **Access the Azure Portal**:
   - Open the Azure portal and navigate to the **App Service** hosting your application.
   - Under the **Settings** section, select **Authentication**.

2. **Add a Provider (Microsoft)**:
   - Click on **Add Identity Provider**.
   - Select **Microsoft** as the identity provider.
   - Under **App Registration**, choose the existing app registration or create a new one. In this case, the registration is **azgov-webapp-demo-chat-az**.
   - Set **Supported Account Types** to **Single tenant** to limit sign-ins to the current Azure AD tenant.

3. **Edit Authentication Settings**:
   - **Enabled**: Ensure that authentication is enabled.
   - **Restrict Access**: Set to **Require Authentication**. This ensures that only authenticated users can access the app.
   - **Token Store**: This feature is optional but enables storing tokens in the app service for authenticated users.
   - **Allowed External Redirect URLs**: You may specify external redirect URLs here if needed for your app flow.

##### Example Configuration:
- **App Registration Name**: `az-webapp-demo-chat`
- **Supported Account Types**: Current tenant - Single tenant
- **Application (client) ID**: `00000000-0000-0000-0000-000000000000`
- **Client Secret Setting Name**: `MICROSOFT_PROVIDER_AUTHENTICATION_SECRET`
- **Issuer URL**: `https://sts.windows.net/00000000-0000-0000-0000-000000000000/v2.0`
- **Allowed Token Audiences**: `api://000000000-0000-0000-0000-000000000000`

4. **Configure Additional Authentication Settings**:
   - **Client Application Requirement**: Select **Allow requests only from this application itself**.
   - **Identity Requirement**: Configure based on your app’s needs, such as allowing only specific identities or the current tenant.

#### 2. **App Registration in Azure Active Directory**

The **App Registration** is where you define how users will authenticate against Azure AD when accessing your application.

##### Steps to Configure App Registration:
1. **Navigate to App Registrations**:
   - In the Azure portal, search for **App Registrations** under **Microsoft Entra ID** (formerly Azure AD).
   - Locate the registration for your app, e.g., `az-webapp-demo-chat`.

2. **Set Redirect URIs**:
   Under the **Authentication** tab in the app registration, configure the following URIs:
   - **Web Redirect URIs**:
     ```
     https://az-webapp-demo-chat.azurewebsites.us/getAToken
     ```
     This URI is used to handle the OAuth 2.0 authorization code flow and retrieve the authentication token.
   - **Front-channel Logout URL**:
     ```
     https://az-webapp-demo-chat.azurewebsites.us/logout
     ```
     This URL is used to log out users from the application and Azure AD session.

3. **Configure API Permissions**:
   - Under the **API Permissions** tab, ensure the app has at least the **User.Read** permission granted. This allows the application to access basic profile information of the signed-in user.

4. **Client Secret**:
   - In the **Certificates & Secrets** section, create a new client secret if needed and store the value securely. This secret is referenced as `MICROSOFT_PROVIDER_AUTHENTICATION_SECRET` in your app's environment variables.

#### 3. **Configure Enterprise Application Access (Users and Groups)**

Once authentication is set up, you can configure access controls using Azure AD’s **Enterprise Applications**. This allows you to manage which users or groups can sign in to your application.

##### Steps to Assign Users and Groups:
1. **Navigate to Enterprise Applications**:
   - In the Azure portal, go to **Enterprise Applications** under **Microsoft Entra ID**.

2. **Select the Application**:
   - Find the enterprise application created during app registration (e.g., `azgov-webapp-demo-chat-az`).

3. **Assign Users and Groups**:
   - Under the **Users and Groups** section, click **+ Add user/group**.
   - Search for and select the users or groups who should have access to the application.
   - Assign the appropriate role (if roles are defined in your app).

4. **Verify Access**:
   - Once the users and groups are assigned, they will be able to log into the application using their Azure AD credentials.

---

### Summary of Authentication Configuration

- **App Service Authentication**: Enable and require authentication through the Azure App Service settings, using **Microsoft** as the identity provider.
- **App Registration**: Set up redirect URIs for authentication and logout, and ensure permissions such as **User.Read** are granted.
- **Enterprise Application Users and Groups**: Assign specific users or groups to the enterprise application to control who can log into the app.

By following these steps, you'll ensure that your **Simple Chat Application** is secure and accessible only to authorized users via Azure AD.

### Environment Variables

Ensure the following environment variables are set within your Azure App Service:

Here's a generalized version of your environment file with placeholders, so it can be used for different environments (e.g., Azure Government or Azure Commercial):

```bash
# General Application Settings
SCM_DO_BUILD_DURING_DEPLOYMENT="true"
WEBSITE_HTTPLOGGING_RETENTION_DAYS="7"
FLASK_KEY="<your-flask-secret-key>"

# Application Insights
APPLICATIONINSIGHTS_CONNECTION_STRING="InstrumentationKey=<your-instrumentation-key>;EndpointSuffix=<your-endpoint-suffix>;IngestionEndpoint=<your-ingestion-endpoint>;AADAudience=<your-aad-audience>;ApplicationId=<your-application-id>"
ApplicationInsightsAgent_EXTENSION_VERSION="~3"
APPLICATIONINSIGHTSAGENT_EXTENSION_ENABLED="true"
XDT_MicrosoftApplicationInsights_Mode="default"

# Azure OpenAI
AZURE_OPENAI_API_TYPE="azure"
AZURE_OPENAI_KEY="<your-openai-api-key>"
AZURE_OPENAI_ENDPOINT="<your-openai-endpoint>"
AZURE_OPENAI_API_VERSION="2024-02-15-preview"
AZURE_OPENAI_LLM_MODEL="gpt-4o"
AZURE_OPENAI_EMBEDDING_MODEL="text-embedding-ada-002"

# Azure Cosmos DB
AZURE_COSMOS_ENDPOINT="<your-cosmosdb-endpoint>"
AZURE_COSMOS_KEY="<your-cosmosdb-key>"
AZURE_COSMOS_DB_NAME="SimpleChat"
AZURE_COSMOS_DOCUMENTS_CONTAINER_NAME="documents"
AZURE_COSMOS_CONVERSATIONS_CONTAINER_NAME="conversations"

# Azure AI Search
AZURE_AI_SEARCH_ENDPOINT="<your-ai-search-endpoint>"
AZURE_AI_SEARCH_KEY="<your-ai-search-key>"
AZURE_AI_SEARCH_USER_INDEX="simplechat-user-index"
AZURE_AI_SEARCH_GROUP_INDEX="simplechat-group-index"

# Azure Document Intelligence
AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT="<your-document-intelligence-endpoint>"
AZURE_DOCUMENT_INTELLIGENCE_KEY="<your-document-intelligence-key>"

# Azure AD Authentication
WEBSITE_AUTH_AAD_ALLOWED_TENANTS="<your-allowed-tenant-id>"
#this is added automatically by the Azure Portal when you add identity provider.
MICROSOFT_PROVIDER_AUTHENTICATION_SECRET="<your-authentication-secret>" 
CLIENT_ID="<your-client-id>"
TENANT_ID="<your-tenant-id>"
```

#### Explanation of Placeholders:

- Replace `<your-flask-secret-key>`, `<your-instrumentation-key>`, `<your-endpoint-suffix>`, etc., with the appropriate values for your environment.
- **Azure Government** and **Azure Commercial** will require different values for `AZURE_OPENAI_ENDPOINT`, `AZURE_COSMOS_ENDPOINT`, `AZURE_AI_SEARCH_ENDPOINT`, and other endpoints, depending on the region (e.g., `*.azure.us` for Azure Government and `*.azure.com` for Azure Commercial).
- **Azure AD Tenant Settings** should also be adjusted based on the tenants allowed in your specific application.

This generalization allows you to switch between environments by simply updating the placeholders.

### Installation

1. Clone the repository to your local environment:
   ```bash
   git clone https://github.com/your-repo/SimpleChat.git
   cd SimpleChat
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Deploy the application to **Azure App Service** using your preferred method (Azure CLI, Visual Studio Code, etc.). Ensure that the environment variables are properly configured in the Azure environment.

### Running the Application

- **Locally**: You can run the application locally for testing:
   ```bash
   flask run
   ```

- **On Azure**: After deployment, navigate to the **Azure App Service** URL to interact with the application.

### Azure Government Configuration

For deployments in **Azure Government**, ensure that the endpoints for **Azure OpenAI**, **Azure Cosmos DB**, **Azure Cognitive Search**, and **Azure Document Intelligence** are set to the correct `.azure.us` suffix.

## Usage

1. **Login**: Users must log in via Azure Active Directory.
2. **Chat**: Start a conversation with the AI or retrieve previous conversations.
3. **Upload Documents**: Upload documents in various formats and use hybrid search to enhance the AI's responses with custom data.
4. **Manage Documents**: View, delete, and upload new versions of documents.
5. **Profile**: View user profile details obtained from AAD.

### User Workflow

The **Simple Chat Application** provides a streamlined user experience for interacting with an AI-powered chat system, enhanced by document retrieval through Azure AI Search. Below is an overview of the typical workflow a user will follow when interacting with the application.

#### 1. **Logging into the Application**

To access the application's features, users must log in using their Azure Active Directory (Azure AD) credentials.

- **Login Page**: Users are directed to a login page, where they authenticate using their Azure AD account.
- **Authentication via Azure AD**: Once users sign in, their session is established, allowing access to the application’s functionality. The session is managed securely using Azure AD tokens.
- **User Profile**: After login, users can view their profile information (name, email, etc.) by navigating to the profile page.

#### 2. **Starting a Chat**

After logging in, users can start a conversation with the AI directly from the chat interface.

- **Navigating to the Chat Page**: Users can click on "Start New Chat" in the navigation bar. This leads to a clean interface for interacting with the AI.
- **Typing Messages**: Users enter text into the message box and submit it by clicking the "Send" button.
- **AI Response**: The AI responds to the user’s messages in real-time, utilizing the Azure OpenAI GPT model to generate conversational responses.
- **Hybrid Search**: Users can enable the "Hybrid Search" option, allowing the AI to retrieve relevant information from previously uploaded documents to enrich its responses.

#### 3. **Uploading a Document**

To enhance AI responses or perform document-specific searches, users can upload their own documents into the system.

- **Navigate to the Document Page**: By selecting the "Your Documents" option in the navigation bar, users are taken to the document management page.
- **Document Upload**: Users can upload a variety of document formats (e.g., PDF, Word, Excel, images) by selecting a file and clicking the "Upload Document" button.
- **Document Processing**: Once uploaded, the document is processed using Azure Document Intelligence, which extracts text and relevant information from the file.
- **Document Storage**: The extracted text is chunked into smaller parts, embedded, and indexed in Azure AI Search for future retrieval.

#### 4. **Using Hybrid Search in a Chat**

With documents uploaded, users can enhance the AI's responses by utilizing the hybrid search functionality.

- **Enable Hybrid Search**: While chatting, users can check the "Enable hybrid search on my documents" option.
- **AI Augmented Responses**: The AI will retrieve relevant content from the user's documents and cite the information within its responses. For instance, if a user asks a question related to a document, the AI will include excerpts and reference the document by file name and page number.

#### 5. **Viewing and Managing Documents**

Users can view and manage their uploaded documents through the document management interface.

- **Document List**: On the "Your Documents" page, users can view a list of all uploaded documents, including details such as the file name, upload date, and version.
- **Delete Documents**: Users can delete individual documents, which removes them from both Azure Cosmos DB (document metadata) and Azure AI Search (document index).
- **Document Versions**: Each document is stored with version control, allowing users to track and manage multiple versions of the same file.

#### 6. **Managing Conversations**

All user conversations are stored in Azure Cosmos DB, allowing users to revisit previous chats.

- **View Past Conversations**: Users can click on "Your Conversations" in the navigation bar to view a list of all previous conversations.
- **Resuming a Conversation**: By selecting a conversation, users can review previous exchanges and continue chatting from where they left off.
- **Conversation History**: The application maintains a limited history of the last 10 messages within each conversation for context.

---

This intuitive workflow makes it easy for users to chat with the AI, enhance responses with document data, and manage both conversations and documents.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
