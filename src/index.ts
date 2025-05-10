import express, { Request, Response } from "express";
import { exec } from "child_process";
import path from "path";
import fs from "fs";
import simpleGit from "simple-git";
import cors from 'cors';

// Initialize the Express app
const app = express();
app.use(express.json());

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const git = simpleGit();
const TEMP_DIR = path.join(__dirname, "temp");

// Ensure temp directory exists
if (!fs.existsSync(TEMP_DIR)) {
  fs.mkdirSync(TEMP_DIR, { recursive: true });
}

// Helper function to recursively list all files in a directory
function listAllFiles(dir: string, fileList: string[] = []): string[] {
  const files = fs.readdirSync(dir);

  files.forEach((file) => {
    const filePath = path.join(dir, file);
    if (fs.statSync(filePath).isDirectory()) {
      // Skip .git directory
      if (file !== ".git") {
        fileList = listAllFiles(filePath, fileList);
      }
    } else {
      fileList.push(filePath);
    }
  });

  return fileList;
}

// Helper function to clone the GitHub repository dynamically
async function cloneRepository(gitUrl: string): Promise<string> {
  const repoName = gitUrl.split("/").pop()?.replace(".git", "") || "repo";
  const repoPath = path.join(TEMP_DIR, repoName);

  console.log(`Cloning repository to: ${repoPath}`);

  // Remove any previous clone of the repository
  if (fs.existsSync(repoPath)) {
    console.log(`Removing existing directory: ${repoPath}`);
    fs.rmSync(repoPath, { recursive: true, force: true });
  }

  try {
    // Clone the repository
    console.log(`Starting clone of: ${gitUrl}`);
    await git.clone(gitUrl, repoPath);
    console.log(`Successfully cloned to: ${repoPath}`);

    // Verify the clone
    if (!fs.existsSync(repoPath)) {
      throw new Error(
        `Repository directory not found after clone: ${repoPath}`
      );
    }

    return repoPath;
  } catch (error: any) {
    console.error(`Error cloning repository: ${error.message}`);
    throw new Error(`Failed to clone repository: ${error.message}`);
  }
}

// Helper function to run Semgrep on the cloned repository
function runSemgrep(directory: string): Promise<string> {
  return new Promise((resolve, reject) => {
    console.log(`Running Semgrep on directory: ${directory}`);

    // Verify directory exists
    if (!fs.existsSync(directory)) {
      reject(`Directory does not exist: ${directory}`);
      return;
    }

    // List all files in the repository
    const allFiles = listAllFiles(directory);
    console.log(`All files in repository: ${allFiles.join("\n")}`);

    // Create a simple, local rule file
    const ruleFile = path.join(directory, "semgrep-rule.yml");
    const ruleContent = `
rules:
  - id: console-log
    pattern: console.log(...)
    message: "Console logging in code"
    languages: [javascript, typescript]
    severity: WARNING
    
  - id: eval-usage
    pattern: eval(...)
    message: "Use of eval"
    languages: [javascript, typescript]
    severity: ERROR
    `;
    fs.writeFileSync(ruleFile, ruleContent);

    // Run Semgrep with locally created rule
    console.log(`Running Semgrep with custom rule: ${ruleFile}`);

    exec(
      `cd ${directory} && semgrep scan --config=${ruleFile} . --json --verbose --disable-nosem --no-rewrite-rule-ids --timeout=0 --max-memory=0 --max-target-bytes=0`,
      (error, stdout, stderr) => {
        // Clean up rule file
        if (fs.existsSync(ruleFile)) {
          fs.unlinkSync(ruleFile);
        }

        if (error) {
          console.error(`Semgrep error: ${error.message}`);
          console.error(`Semgrep stderr: ${stderr}`);
          reject(`Error running Semgrep: ${stderr}`);
        } else {
          console.log(`Semgrep output: ${stdout}`);
          resolve(stdout);
        }
      }
    );
  });
}

// POST /analyze: Endpoint to receive a GitHub repository URL for analysis
app.post("/analyze", async (req: Request, res: Response) => {
  const { gitUrl } = req.body;

  if (!gitUrl) {
    return res
      .status(400)
      .json({ error: "Please provide a gitUrl in the request body." });
  }

  console.log(`Received analysis request for: ${gitUrl}`);

  try {
    // Step 1: Clone the repository dynamically
    const repoPath = await cloneRepository(gitUrl);

    // Step 2: Run Semgrep on the cloned codebase
    const semgrepOutput = await runSemgrep(repoPath);

    // Step 3: Parse and return the vulnerabilities found
    const vulnerabilities = JSON.parse(semgrepOutput);
    console.log(
      `Analysis complete. Found ${vulnerabilities.results?.length || 0} results`
    );

    // Send back the results
    res.json({ vulnerabilities });

    // Step 4: Cleanup the cloned repository
    console.log(`Cleaning up: ${repoPath}`);
    fs.rmSync(repoPath, { recursive: true, force: true });
  } catch (error: any) {
    console.error(`Analysis failed: ${error.message}`);
    res.status(500).json({ error: `Analysis failed: ${error.message}` });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Temporary directory: ${TEMP_DIR}`);
});
