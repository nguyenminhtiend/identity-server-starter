#!/bin/bash

echo ""
echo "🔧 Running code quality checks..."
echo ""

# Run formatter
echo "📝 Running formatter..."
pnpm format
if [ $? -ne 0 ]; then
  echo "❌ Format failed"
  exit 1
fi
echo "✅ Format complete"
echo ""

# Run linter
echo "🔍 Running linter..."
pnpm lint:fix
if [ $? -ne 0 ]; then
  echo "❌ Lint failed"
  exit 1
fi
echo "✅ Lint complete"
echo ""

# Run type checker
echo "🔎 Running type checker..."
pnpm typecheck
if [ $? -ne 0 ]; then
  echo "❌ Type check failed"
  exit 1
fi
echo "✅ Type check complete"
echo ""

echo "✅ All code quality checks passed!"
echo ""
