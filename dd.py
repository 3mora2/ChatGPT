import docker
import os

# Define the path to your Docker Compose YAML file
compose_file_path = 'path/to/your/docker-compose.yml'

# Initialize the Docker client
client = docker.from_env()

# Define environment variables that may contain sensitive information
# You should load these from a secure source (e.g., environment files or secret management)
env_vars = {
    "sql_host": "mysqlIP",
    "sql_userName": "root",
    "sql_port": "3306",
    "sql_password": "mysql密码"
}

# Build the environment variable dictionary
environment = {key: os.getenv(key, value) for key, value in env_vars.items()}

# Use Docker Compose to manage your services
try:
    # Create a Docker Compose project
    project = docker.compose.project.from_file(
        compose_file_path, project_name='my_project'
    )

    # Start the services defined in the Docker Compose file
    project.up(environment=environment)

    # You can perform other operations here, such as stopping, restarting, or inspecting services

finally:
    # Clean up and stop the services when done
    project.down()

# Close the Docker client when you're finished
client.close()