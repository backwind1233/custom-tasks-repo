const fs = require('fs');
const path = require('path');
const matter = require('gray-matter');

function generateMetadata() {
  const tasks = [];
  const rootDir = path.join(__dirname, '..');

  // Read all directories in the root
  const entries = fs.readdirSync(rootDir, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      const taskMdPath = path.join(rootDir, entry.name, 'task.md');

      // Check if task.md exists
      if (fs.existsSync(taskMdPath)) {
        try {
          const fileContent = fs.readFileSync(taskMdPath, 'utf8');
          const { data } = matter(fileContent);

          // Extract only properties available from the YAML frontmatter
          if (data.id && data.name) {
            tasks.push({
              id: data.id,
              name: data.name,
              path: entry.name
            });
          }
        } catch (error) {
          console.error(`Error processing ${taskMdPath}:`, error.message);
        }
      }
    }
  }

  // Write metadata.json
  const metadata = {
    tasks: tasks
  };

  fs.writeFileSync(
    path.join(rootDir, 'metadata.json'),
    JSON.stringify(metadata, null, 2),
    'utf8'
  );

  console.log(`Generated metadata.json with ${tasks.length} tasks`);
}

generateMetadata();
