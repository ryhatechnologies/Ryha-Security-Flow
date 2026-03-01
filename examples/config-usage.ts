import { ConfigManager } from '../config';
import { SetupWizard } from '../cli/setup-wizard';

/**
 * Example: Initialize and use ConfigManager
 */
async function exampleBasicUsage() {
  console.log('=== Example 1: Basic Configuration Loading ===\n');

  // Create a config manager instance
  const config = new ConfigManager({
    validateOnInit: true,
    enableHotReload: true,
  });

  // Get the full config
  const fullConfig = config.getConfig();
  console.log('Full configuration loaded:', JSON.stringify(fullConfig, null, 2));

  // Get a specific section
  const serverConfig = config.getSection('server');
  console.log('\nServer config:', serverConfig);

  // Get a specific value
  const port = config.get('server.port', 3000);
  console.log('Server port:', port);

  // Cleanup
  config.destroy();
}

/**
 * Example: Update and save configuration
 */
async function exampleUpdateConfig() {
  console.log('\n=== Example 2: Update and Save Configuration ===\n');

  const config = new ConfigManager({ validateOnInit: false });

  // Update a section
  config.setSection('agents', {
    maxParallel: 20,
    retryAttempts: 5,
  });

  // Update a specific value
  config.set('server.port', 4000);

  // Save to file
  config.saveConfig();
  console.log('Configuration updated and saved!');

  config.destroy();
}

/**
 * Example: Secure API key handling
 */
async function exampleSecureApiKey() {
  console.log('\n=== Example 3: Secure API Key Handling ===\n');

  const config = new ConfigManager();

  // Store an API key (encrypted)
  const apiKey = 'sk-ant-exampleapikey123';
  config.setApiKey(apiKey, 'copilot');
  console.log('API key stored (encrypted)');

  // Retrieve and decrypt
  const retrievedKey = config.getApiKey('copilot');
  console.log('Retrieved API key:', retrievedKey === apiKey ? 'MATCH (decrypted successfully)' : 'MISMATCH');

  config.destroy();
}

/**
 * Example: Watch for configuration changes
 */
async function exampleWatchConfig() {
  console.log('\n=== Example 4: Watch for Configuration Changes ===\n');

  const config = new ConfigManager({ enableHotReload: true });

  // Set up a watcher
  config.watch('my-watcher', (updatedConfig) => {
    console.log('Configuration changed! New server port:', updatedConfig.server?.port);
  });

  // Simulate a change
  setTimeout(() => {
    config.set('server.port', 5000);
    console.log('Triggered configuration change...');
  }, 1000);

  // Cleanup after demo
  setTimeout(() => {
    config.unwatch('my-watcher');
    config.destroy();
  }, 2000);
}

/**
 * Example: Run setup wizard
 */
async function exampleSetupWizard() {
  console.log('\n=== Example 5: Setup Wizard ===\n');

  const wizard = new SetupWizard({
    interactive: true,
    validateTools: false,
  });

  const success = await wizard.runSetup();
  console.log(`\nSetup wizard completed: ${success ? 'SUCCESS' : 'FAILED'}`);
}

/**
 * Run all examples
 */
async function runAllExamples() {
  try {
    await exampleBasicUsage();
    await exampleUpdateConfig();
    await exampleSecureApiKey();
    // await exampleWatchConfig(); // Uncomment to test
    // await exampleSetupWizard(); // Uncomment to test
  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Run examples if this file is executed directly
if (require.main === module) {
  runAllExamples();
}

export {
  exampleBasicUsage,
  exampleUpdateConfig,
  exampleSecureApiKey,
  exampleWatchConfig,
  exampleSetupWizard,
};
