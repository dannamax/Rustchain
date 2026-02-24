const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const path = require('path');

async function run() {
  try {
    // Get inputs
    const wallet = core.getInput('wallet', { required: true });
    const readmePath = core.getInput('readme-path') || 'README.md';
    const badgeLabel = core.getInput('badge-label') || 'RustChain Mining';
    
    // Validate wallet
    if (!wallet || wallet.trim().length === 0) {
      throw new Error('Wallet parameter is required');
    }
    
    // Get badge data from RustChain API
    const badgeUrl = `https://50.28.86.131/api/badge/${encodeURIComponent(wallet)}`;
    core.info(`Fetching badge data from: ${badgeUrl}`);
    
    const response = await fetch(badgeUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch badge data: ${response.status} ${response.statusText}`);
    }
    
    const badgeData = await response.json();
    core.info(`Badge data received: ${JSON.stringify(badgeData)}`);
    
    // Read README file
    if (!fs.existsSync(readmePath)) {
      throw new Error(`README file not found at: ${readmePath}`);
    }
    
    let readmeContent = fs.readFileSync(readmePath, 'utf8');
    
    // Create badge markdown
    const badgeMarkdown = `![${badgeLabel}](https://img.shields.io/endpoint?url=${encodeURIComponent(badgeUrl)})`;
    
    // Check if badge already exists in README
    const badgeRegex = /!\[${badgeLabel}\]\(https:\/\/img\.shields\.io\/endpoint\?url=https%3A%2F%2F50\.28\.86\.131%2Fapi%2Fbadge%2F[^)]+\)/g;
    
    if (badgeRegex.test(readmeContent)) {
      // Update existing badge
      readmeContent = readmeContent.replace(badgeRegex, badgeMarkdown);
      core.info('Updated existing RustChain badge in README');
    } else {
      // Add new badge (insert after first heading or at the beginning)
      const lines = readmeContent.split('\n');
      let insertIndex = 0;
      
      // Find first heading
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].startsWith('# ')) {
          insertIndex = i + 1;
          break;
        }
      }
      
      lines.splice(insertIndex, 0, '', badgeMarkdown, '');
      readmeContent = lines.join('\n');
      core.info('Added new RustChain badge to README');
    }
    
    // Write updated README
    fs.writeFileSync(readmePath, readmeContent);
    core.info('README updated successfully');
    
    // Set output
    core.setOutput('badge-markdown', badgeMarkdown);
    core.setOutput('badge-url', badgeUrl);
    
  } catch (error) {
    core.setFailed(error.message);
    throw error;
  }
}

run();