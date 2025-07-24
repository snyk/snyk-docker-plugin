#!/usr/bin/env node

const { getImageType } = require('./dist/image-type');

function testImageType() {
  const testImages = [
    'alpine:latest',
    'nginx:1.21',
    'us-docker.pkg.dev/polaris-gcp-gar/polaris/container-integrations:dev',
    'docker-archive:/tmp/image.tar',
    'oci-archive:/tmp/image.tar',
    '/tmp/image.tar'
  ];

  console.log('🔍 Testing image type detection:');
  testImages.forEach(image => {
    const type = getImageType(image);
    console.log(`  ${image} → ${type}`);
  });
}

testImageType(); 