# Railway Deployment Guide for Flask Resume Matcher

## Required Files for Railway Deployment

### 1. requirements.txt
```txt
Flask==2.3.3
PyPDF2==3.0.1
python-docx==0.8.11
Werkzeug==2.3.7
```

### 2. Procfile (optional but recommended)
```
web: python app.py
```

### 3. railway.json (optional configuration)
```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "python app.py"
  }
}
```

## Key Deployment Configuration in app.py

### Port Configuration
```python
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
```

**Railway-specific logic:**
- Uses `os.environ.get('PORT', 5000)` to read Railway's dynamic port
- Binds to `0.0.0.0` to accept external connections
- Disables debug mode for production

### File Upload Directory Setup
```python
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs('uploads', exist_ok=True)
```

**Railway considerations:**
- Creates uploads directory if it doesn't exist
- Uses ephemeral storage (files are temporary)
- Files are cleaned up after processing

### Temporary File Handling
```python
# Save file temporarily
resume_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
resume_file.save(resume_path)
resume_text = matcher.extract_text(resume_path)
os.remove(resume_path)  # Clean up immediately
```

**Railway-optimized approach:**
- Saves files temporarily to process them
- Immediately removes files after extraction
- Prevents disk space accumulation on ephemeral storage

## Railway Deployment Steps

### Method 1: GitHub Integration
1. Push your code to GitHub repository
2. Connect Railway to your GitHub account
3. Select the repository
4. Railway will auto-detect Flask app and deploy

### Method 2: Railway CLI
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Initialize project
railway init

# Deploy
railway up
```

### Method 3: Direct Git Deploy
```bash
# Add Railway remote
railway init
git add .
git commit -m "Deploy to Railway"
railway up
```

## Environment Variables (if needed)
Set in Railway dashboard under Variables tab:
```
FLASK_ENV=production
PORT=5000  # Railway sets this automatically
```

## Important Railway Considerations

### 1. Ephemeral Storage
- Files uploaded are temporary
- No persistent file storage
- App handles this by processing and deleting files immediately

### 2. Memory Limits
- Railway has memory limits on free tier
- Large PDF processing might hit limits
- Consider file size restrictions

### 3. Cold Starts
- App may sleep after inactivity
- First request after sleep takes longer
- Consider Railway Pro for always-on service

### 4. Build Process
Railway will automatically:
- Detect Python application
- Install dependencies from requirements.txt
- Set up the environment
- Start the application on the specified port

## Troubleshooting

### Common Issues:
1. **Port binding error**: Ensure using `os.environ.get('PORT', 5000)`
2. **File upload issues**: Check file size limits and temporary storage
3. **Memory errors**: Monitor memory usage with large files
4. **Cold start delays**: First request after sleep is slower

### Logs Access:
```bash
railway logs
```

## Production Optimizations

### 1. Add Error Handling
```python
@app.errorhandler(413)
def too_large(e):
    return "File is too large", 413
```

### 2. File Size Limits
```python
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
```

### 3. Health Check Endpoint
```python
@app.route('/health')
def health_check():
    return {'status': 'healthy'}, 200
```

This deployment configuration ensures your Flask resume matcher works seamlessly on Railway's platform with proper port binding, file handling, and production settings.
