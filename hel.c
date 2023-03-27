#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define the maximum password length
#define MAX_PASSWORD_LENGTH 50

// Define the maximum number of passwords that can be stored
#define MAX_PASSWORDS 10

// Define the structure of a password block
struct password_block {
  int index;
  char password[MAX_PASSWORD_LENGTH + 1];
  char prev_hash[SHA256_DIGEST_LENGTH * 2 + 1];
  char hash[SHA256_DIGEST_LENGTH * 2 + 1];
};

// Define the global password block array
struct password_block password_chain[MAX_PASSWORDS];

// Define the current password block index
int current_index = 0;

// Function to calculate the SHA256 hash of a given string
void sha256(char *string, char outputBuffer[SHA256_DIGEST_LENGTH * 2 + 1]) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, string, strlen(string));
  SHA256_Final(hash, &sha256);
  int i = 0;
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
  }
  outputBuffer[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// Function to add a new password block to the chain
void add_password_block(char *password) {
  struct password_block new_block;
  new_block.index = current_index;
  strncpy(new_block.password, password, MAX_PASSWORD_LENGTH);
  new_block.password[MAX_PASSWORD_LENGTH] = '\0';
  strncpy(new_block.prev_hash, password_chain[current_index - 1].hash,
          SHA256_DIGEST_LENGTH * 2 + 1);
  sha256((char *)&new_block, new_block.hash);
  password_chain[current_index] = new_block;
  current_index++;
}

// Function to print the entire password chain
void print_password_chain() {
  int i;
  for (i = 0; i < current_index; i++) {
    printf("Block %d:\n", password_chain[i].index);
    printf("Password: %s\n", password_chain[i].password);
    printf("Previous Hash: %s\n", password_chain[i].prev_hash);
    printf("Hash: %s\n", password_chain[i].hash);
    printf("\n");
  }
}

// Function to find a password block by index
struct password_block *find_password_block(int index) {
  if (index >= 0 && index < current_index) {
    return &password_chain[index];
  }
  return NULL;
}

// Function to delete a password block by index
void delete_password_block(int index) {
  if (index >= 0 && index < current_index) {
    int i;
    for (i = index; i < current_index - 1; i++) {
      password_chain[i] = password_chain[i + 1];
    }
    current_index--;
  }
}

// Function to edit a password block by index
void edit_password_block(int index, char *new_password) {
  if (index >= 0 && index < current_index) {
    struct password_block *block_to_edit = &password_chain[index];
    strncpy(block_to_edit->password, new_password, MAX_PASSWORD_LENGTH);
    block_to_edit->password[MAX_PASSWORD_LENGTH] = '\0';
    sha256((char *)block_to_edit, block_to_edit->hash);

    // update the hashes of subsequent blocks
    int i;
    for (i = index + 1; i < current_index; i++) {
      struct password_block *current_block = &password_chain[i];
      strncpy(current_block->prev_hash, (current_block - 1)->hash,
              SHA256_DIGEST_LENGTH * 2 + 1);
      sha256((char *)current_block, current_block->hash);
    }
  }
}

int main() {
  int choice, index;
  char password[MAX_PASSWORD_LENGTH + 1];

  do {
    printf("Password Manager Menu:\n");
    printf("1. Add a password\n");
    printf("2. See all passwords\n");
    printf("3. Delete a password\n");
    printf("4. Edit a password\n");
    printf("5. Quit\n");
    printf("Enter your choice (1-5): ");
    scanf("%d", &choice);

    switch (choice) {
    case 1:
      printf("Enter a password (maximum %d characters): ", MAX_PASSWORD_LENGTH);
      scanf("%s", password);
      add_password_block(password);
      printf("Password added successfully.\n\n");
      break;
    case 2:
      printf("Password Chain:\n");
      print_password_chain();
      break;
    case 3:
      printf("Enter the index of the password to delete: ");
      scanf("%d", &index);
      delete_password_block(index);
      printf("Password deleted successfully.\n\n");
      break;
    case 4:
      printf("Enter the index of the password to edit: ");
      scanf("%d", &index);
      printf("Enter the new password (maximum %d characters): ",
             MAX_PASSWORD_LENGTH);
      scanf("%s", password);
      edit_password_block(index, password);
      printf("Password edited successfully.\n\n");
      break;
    case 5:
      printf("Goodbye!\n");
      break;
    default:
      printf("Invalid choice. Please choose a number between 1 and 5.\n\n");
      break;
    }
  } while (choice != 5);

  return 0;
}
