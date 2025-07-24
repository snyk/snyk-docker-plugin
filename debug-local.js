#!/usr/bin/env node

const plugin = require('./dist');

async function scanDockerImage() {
  try {
    // Get image from command line argument or use default Docker archive
    const imageName = process.argv[2] || 'us-docker.pkg.dev/polaris-gcp-gar/polaris/container-integrations:dev';
    
    console.log(`🔍 Scanning Docker target: ${imageName}`);
    
    console.time('Scan Duration');
    
    // Set breakpoint here to debug the scan function
    const result = await plugin.scan({
      path: imageName,                // Docker image:tag
      'app-vulns': true,             // Include application vulnerabilities
      // platform: 'linux/arm64',      // Let it auto-detect platform
      imageSavePath: '/tmp/snyk-debug-scan', // Use custom path for debugging
    });
    
    console.timeEnd('Scan Duration');
    
    // Set breakpoint here to inspect results
    console.log('\n✅ Scan completed successfully!');
    console.log(`📊 Found ${result.scanResults.length} scan result(s)`);
    
    // Show summary for each scan result
    result.scanResults.forEach((scanResult, index) => {
      console.log(`\n📋 Result ${index + 1}:`);
      console.log(`   Target: ${scanResult.target.image}`);
      console.log(`   OS Type: ${scanResult.identity.type}`);
      console.log(`   Facts: ${scanResult.facts.length} items`);
      
      // Show what types of facts were found
      const factTypes = scanResult.facts.map(fact => fact.type);
      console.log(`   Fact types: ${factTypes.join(', ')}`);
    });
    
    // Optionally show full JSON (comment out if too verbose)
    // console.log('\n🔍 Full results:');
    // console.log(JSON.stringify(result, null, 2));
    
  } catch (error) {
    console.error('❌ Scan failed:', error.message);
    console.error('Full error stack:', error.stack);
  }
}

// Run the scan
scanDockerImage();
