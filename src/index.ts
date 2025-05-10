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
  origin: '*', // Consider restricting this in production
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
    console.log(`Found ${allFiles.length} files in repository`);

    // Run Semgrep with OWASP Top 10 ruleset directly from the registry
    console.log(`Running Semgrep with OWASP Top 10 ruleset`);

    // Command using registry ruleset for OWASP Top 10
    exec(
      `cd ${directory} && semgrep scan --config=p/owasp-top-ten . --json --verbose --disable-nosem --no-rewrite-rule-ids --timeout=0 --max-memory=0 --max-target-bytes=0`,
      { maxBuffer: 10 * 1024 * 1024 }, // Increase buffer size for large outputs
      (error, stdout, stderr) => {
        if (error && error.code !== 1) { // Semgrep returns 1 when it finds issues, but that's not a failure
          console.error(`Semgrep error: ${error.message}`);
          console.error(`Semgrep stderr: ${stderr}`);
          reject(`Error running Semgrep: ${stderr}`);
        } else {
          console.log(`Semgrep scan completed`);
          resolve(stdout);
        }
      }
    );
  });
}

// Add an option to use both standard and OWASP rules
function runSemgrepWithMultipleRulesets(directory: string): Promise<string> {
  return new Promise((resolve, reject) => {
    console.log(`Running Semgrep with multiple rulesets on directory: ${directory}`);

    // Verify directory exists
    if (!fs.existsSync(directory)) {
      reject(`Directory does not exist: ${directory}`);
      return;
    }

    // Add a custom ruleset for checks not covered in OWASP
    const ruleFile = path.join(directory, "custom-rules.yml");
    const customRuleContent = `
rules:
  - id: custom-console-log
    pattern: console.log(...)
    message: "Console logging in code"
    languages: [javascript, typescript]
    severity: INFO
    `;
    fs.writeFileSync(ruleFile, customRuleContent);

    // Command to run with both OWASP and language-specific rulesets
    exec(
      `cd ${directory} && semgrep scan --config=p/owasp-top-ten,p/javascript,p/typescript,p/nodejs,${ruleFile} . --json --verbose --disable-nosem --no-rewrite-rule-ids --timeout=0 --max-memory=0 --max-target-bytes=0`,
      { maxBuffer: 10 * 1024 * 1024 }, // Increased buffer size
      (error, stdout, stderr) => {
        // Clean up rule file
        if (fs.existsSync(ruleFile)) {
          fs.unlinkSync(ruleFile);
        }

        if (error && error.code !== 1) { // Semgrep returns 1 when it finds issues
          console.error(`Semgrep error: ${error.message}`);
          console.error(`Semgrep stderr: ${stderr}`);
          reject(`Error running Semgrep: ${stderr}`);
        } else {
          console.log(`Semgrep scan completed`);
          resolve(stdout);
        }
      }
    );
  });
}

// POST /analyze: Endpoint to receive a GitHub repository URL for analysis
app.post("/analyze", async (req: Request, res: Response) => {
  const { gitUrl, ruleType = "owasp" } = req.body;

  if (!gitUrl) {
    return res
      .status(400)
      .json({ error: "Please provide a gitUrl in the request body." });
  }

  console.log(`Received analysis request for: ${gitUrl} with ruleType: ${ruleType}`);

  try {
    // Step 1: Clone the repository dynamically
    const repoPath = await cloneRepository(gitUrl);

    // Step 2: Run Semgrep with appropriate ruleset
    let semgrepOutput;
    if (ruleType === "owasp") {
      semgrepOutput = await runSemgrep(repoPath);
    } else if (ruleType === "comprehensive") {
      semgrepOutput = await runSemgrepWithMultipleRulesets(repoPath);
    } else {
      throw new Error("Invalid ruleType. Use 'owasp' or 'comprehensive'");
    }

    // Step 3: Parse and return the vulnerabilities found
    const vulnerabilities = JSON.parse(semgrepOutput);
    console.log(
      `Analysis complete. Found ${vulnerabilities.results?.length || 0} results`
    );

    // Add OWASP category mapping for better understanding
    const enhancedResults = vulnerabilities.results?.map((result: any) => {
      // Extract OWASP category from rule ID if available
      const owaspMatch = result.check_id.match(/owasp\-(.*?)\-/);
      if (owaspMatch && owaspMatch[1]) {
        const category = owaspMatch[1].toUpperCase();
        result.owasp_category = `A${category}:2017`;
      }
      return result;
    });

    // Send back the results with OWASP mapping
    res.json({ 
      vulnerabilities: {
        ...vulnerabilities,
        results: enhancedResults || vulnerabilities.results
      } 
    });

    // Step 4: Cleanup the cloned repository
    console.log(`Cleaning up: ${repoPath}`);
    fs.rmSync(repoPath, { recursive: true, force: true });
  } catch (error: any) {
    console.error(`Analysis failed: ${error.message}`);
    res.status(500).json({ error: `Analysis failed: ${error.message}` });
  }
});

// GET /rules: Endpoint to list available rulesets
app.get("/rules", (req: Request, res: Response) => {
  res.json({
    availableRuleTypes: [
      {
        id: "owasp",
        name: "OWASP Top 10",
        description: "Scans for OWASP Top 10 vulnerabilities"
      },
      {
        id: "comprehensive",
        name: "Comprehensive Scan",
        description: "Includes OWASP Top 10, language-specific rules, and custom checks"
      }
    ]
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Temporary directory: ${TEMP_DIR}`);
});