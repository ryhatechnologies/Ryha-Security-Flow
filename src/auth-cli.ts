import { copilotAuth } from './auth/copilot-auth';

async function main() {
  try {
    const isAuth = await copilotAuth.isAuthenticated();

    if (isAuth) {
      console.log('✓ Already authenticated');
      console.log('\nAvailable models:');
      copilotAuth.getAvailableModels().forEach(model => {
        console.log(`  - ${model.name} (${model.id})`);
      });

      console.log('\nTesting connection...');
      const response = await copilotAuth.sendChatMessage(
        'Hello! Just testing the connection.',
        'claude-3-5-sonnet-20241022'
      );
      console.log('\n✓ Connection test successful!');
      console.log('Response preview:', response.substring(0, 100) + '...');
    } else {
      console.log('Starting authentication...\n');
      await copilotAuth.authenticate();
      console.log('\n✓ Authentication complete!');
      console.log('You can now start the server: npm run start');
    }
  } catch (error) {
    console.error('❌ Error:', (error as Error).message);
    process.exit(1);
  }
}

main();
