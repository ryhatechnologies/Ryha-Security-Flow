/**
 * Authorization System Usage Examples
 * Demonstrates how to use AuthDocument and AuthValidator
 */

import { AuthDocument, AuthValidator, TestingType } from '../src/compliance';
import fs from 'fs';
import path from 'path';

/**
 * Example 1: Create a new authorization document
 */
export function example1_createAuthDocument(): void {
  console.log('Example 1: Creating a new authorization document...\n');

  const authDoc = new AuthDocument(
    'Acme Corporation',
    'acme.com',
    ['acme.com', '*.acme.com', 'api.acme.com', '10.0.0.0/24'],
    ['customer-data.acme.com', 'production.acme.com', '10.0.1.0/24'],
    new Date('2024-01-15'),
    new Date('2024-02-15'),
    ['network', 'web', 'infrastructure'],
    'John Smith, CEO',
    'JS-2024-0115',
    'Avoid testing during business hours. Contact: security@acme.com'
  );

  // Validate the document
  const validation = authDoc.validate();
  console.log('Validation Result:', validation);

  // Save to file
  const savedPath = authDoc.save();
  console.log(`Document saved to: ${savedPath}`);
  console.log(`Document ID: ${authDoc.id}\n`);

  return authDoc.id;
}

/**
 * Example 2: Load an existing authorization document
 */
export function example2_loadAuthDocument(docId: string): void {
  console.log(`Example 2: Loading authorization document ${docId}...\n`);

  const authDoc = AuthDocument.load(docId);

  if (!authDoc) {
    console.log('Document not found');
    return;
  }

  console.log(`Client: ${authDoc.clientName}`);
  console.log(`Target Domain: ${authDoc.targetDomain}`);
  console.log(`Valid Period: ${authDoc.startDate} to ${authDoc.endDate}`);
  console.log(`Days Remaining: ${authDoc.getDaysRemaining()}`);
  console.log(`Testing Types: ${authDoc.testingType.join(', ')}`);
  console.log(`Is Valid: ${authDoc.isValid()}\n`);
}

/**
 * Example 3: Check scope and target validation
 */
export function example3_validateScope(docId: string): void {
  console.log(`Example 3: Validating scope for document ${docId}...\n`);

  const authDoc = AuthDocument.load(docId);

  if (!authDoc) {
    console.log('Document not found');
    return;
  }

  const targetsToCheck = [
    'acme.com',
    'www.acme.com',
    'api.acme.com',
    'customer-data.acme.com',
    'external.com',
    '10.0.0.5',
    '10.0.1.5',
  ];

  console.log('Target Scope Validation:');
  targetsToCheck.forEach((target) => {
    const inScope = authDoc.isTargetInScope(target);
    const outOfScope = authDoc.isTargetOutOfScope(target);

    let status = 'UNKNOWN';
    if (inScope && !outOfScope) {
      status = 'IN SCOPE';
    } else if (outOfScope) {
      status = 'OUT OF SCOPE (DENIED)';
    } else if (!inScope) {
      status = 'NOT IN SCOPE';
    }

    console.log(`  ${target}: ${status}`);
  });

  console.log();
}

/**
 * Example 4: Use AuthValidator for pre-scan validation
 */
export function example4_prescanValidation(docId: string): void {
  console.log(`Example 4: Pre-scan validation for document ${docId}...\n`);

  const validator = new AuthValidator();

  // Test 1: Valid scan
  console.log('Test 1: Valid scan request');
  const result1 = validator.validateBeforeScan(
    docId,
    'api.acme.com',
    'web'
  );
  console.log('Result:', {
    isValid: result1.isValid,
    authorized: result1.authorized,
    inScope: result1.inScope,
    errors: result1.errors,
  });
  console.log();

  // Test 2: Invalid scan type
  console.log('Test 2: Unauthorized scan type');
  const result2 = validator.validateBeforeScan(docId, 'acme.com', 'code');
  console.log('Result:', {
    isValid: result2.isValid,
    authorized: result2.authorized,
    errors: result2.errors,
  });
  console.log();

  // Test 3: Out of scope target
  console.log('Test 3: Out of scope target');
  const result3 = validator.validateBeforeScan(
    docId,
    'customer-data.acme.com',
    'web'
  );
  console.log('Result:', {
    isValid: result3.isValid,
    inScope: result3.inScope,
    errors: result3.errors,
  });
  console.log();
}

/**
 * Example 5: Batch validate multiple targets
 */
export function example5_batchValidation(docId: string): void {
  console.log(`Example 5: Batch validating targets for document ${docId}...\n`);

  const validator = new AuthValidator();

  const targets = [
    'www.acme.com',
    'api.acme.com',
    'prod.acme.com',
    'external.com',
  ];

  const results = validator.validateTargetList(docId, targets, 'web');

  console.log('Batch Validation Results:');
  results.forEach((result, target) => {
    console.log(`  ${target}:`);
    console.log(`    Valid: ${result.isValid}`);
    console.log(`    Expected errors: ${result.errors.length > 0}`);
  });
  console.log();
}

/**
 * Example 6: Export authorization in different formats
 */
export function example6_exportFormats(docId: string): void {
  console.log(`Example 6: Exporting authorization document ${docId}...\n`);

  const authDoc = AuthDocument.load(docId);

  if (!authDoc) {
    console.log('Document not found');
    return;
  }

  // Export as Markdown
  const markdown = authDoc.exportAsMarkdown();
  console.log('=== MARKDOWN FORMAT ===');
  console.log(markdown);
  console.log();

  // Export as plain text
  const text = authDoc.exportAsText();
  console.log('=== TEXT FORMAT ===');
  console.log(text);
  console.log();

  // Export as YAML
  const yaml = authDoc.toYAML();
  console.log('=== YAML FORMAT ===');
  console.log(yaml);
}

/**
 * Example 7: List and manage authorization documents
 */
export function example7_listDocuments(): void {
  console.log('Example 7: Listing all authorization documents...\n');

  const validator = new AuthValidator();
  const status = validator.getAuthorizationStatus();

  console.log('Authorization Status:');
  console.log(`  Total Documents: ${status.total}`);
  console.log(`  Valid: ${status.valid}`);
  console.log(`  Expired: ${status.expired}`);
  console.log(`  Expiring Soon (7d): ${status.expiring_soon}`);
  console.log();

  const validAuths = validator.listValidAuthorizations();
  console.log(`Valid Authorizations (${validAuths.length}):`);
  validAuths.forEach((auth) => {
    console.log(`  - ${auth.id} (${auth.clientName}): expires in ${auth.getDaysRemaining()} days`);
  });
  console.log();

  const expiredAuths = validator.listExpiredAuthorizations();
  console.log(`Expired Authorizations (${expiredAuths.length}):`);
  expiredAuths.forEach((auth) => {
    console.log(
      `  - ${auth.id} (${auth.clientName}): expired ${Math.abs(auth.getDaysRemaining())} days ago`
    );
  });
  console.log();
}

/**
 * Example 8: Generate compliance report
 */
export function example8_complianceReport(): void {
  console.log('Example 8: Generating compliance report...\n');

  const validator = new AuthValidator();
  const report = validator.generateComplianceReport();
  console.log(report);
}

/**
 * Example 9: Run all examples
 */
export function runAllExamples(): void {
  console.log('================================================================================');
  console.log('             Authorization System Examples - Ryha Security Flow');
  console.log('================================================================================\n');

  try {
    // Create a new document
    console.log('>>> Running all examples in sequence...\n');

    // Note: In actual usage, provide a pre-existing document ID
    console.log('To run these examples with actual data:');
    console.log('1. Create an authorization document using the CLI');
    console.log('2. Get its document ID');
    console.log('3. Pass it to the example functions\n');

    example7_listDocuments();
    example8_complianceReport();
  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Export default
export default {
  example1_createAuthDocument,
  example2_loadAuthDocument,
  example3_validateScope,
  example4_prescanValidation,
  example5_batchValidation,
  example6_exportFormats,
  example7_listDocuments,
  example8_complianceReport,
  runAllExamples,
};
