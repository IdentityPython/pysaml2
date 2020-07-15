pipeline {
    agent {
        dockerfile { 
            filename 'Dockerfile.build'
        }
    }
    stages {
        stage('Test') {
            steps {
                sh 'pytest'
            }
        }
    }
}
