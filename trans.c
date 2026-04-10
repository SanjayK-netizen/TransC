// Bank-account program reads a random-access file sequentially,
// updates data already written to the file, creates new data to
// be placed in the file, and deletes data previously in the file.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>

#define LOG_FILE "audit.log"
#define MAX_ATTEMPTS 3

// hash function for PIN
unsigned int hashPin(const char *pin);

// log action to audit file
void logAction(const char *action);

// authenticate user with PIN
int authenticateUser(void);

// initialize default PIN
void initPassword(void);

// clientData structure definition
struct clientData
{
    unsigned int acctNum; // account number
    char lastName[15];    // account last name
    char firstName[10];   // account first name
    double balance;       // account balance
};                        // end structure clientData

// prototypes
unsigned int enterChoice(void);
void textFile(FILE *readPtr);
void updateRecord(FILE *fPtr);
void newRecord(FILE *fPtr);
void deleteRecord(FILE *fPtr);
void changePin(void);
void clearScreen(void);
void pauseForEnter(void);
void printWelcomeBanner(void);
void displayMenu(void);

int main(int argc, char *argv[])
{
    FILE *cfPtr;         // credit.dat file pointer
    unsigned int choice; // user's choice

    // fopen opens the file; exits if file cannot be opened
    if ((cfPtr = fopen("credit.dat", "rb+")) == NULL)
    {
        printf("%s: File could not be opened.\n", argv[0]);
        exit(-1);
    }

    // initialize default PIN if needed
    initPassword();

    // authenticate user
    if (!authenticateUser())
    {
        printf("Access denied. Too many failed attempts.\n");
        fclose(cfPtr);
        exit(-1);
    }

    logAction("User logged in");
    clearScreen();
    printWelcomeBanner();

    // enable user to specify action
    while ((choice = enterChoice()) != 6)
    {
        switch (choice)
        {
        // create text file from record file
        case 1:
            textFile(cfPtr);
            break;
        // update record
        case 2:
            updateRecord(cfPtr);
            break;
        // change PIN
        case 3:
            changePin();
            break;
        // create record
        case 4:
            newRecord(cfPtr);
            break;
        // delete existing record
        case 5:
            deleteRecord(cfPtr);
            break;
        // display if user does not select valid choice
        default:
            printf("Invalid selection. Please choose a menu option.\n");
            break;
        } // end switch

        pauseForEnter();
        clearScreen();
        printWelcomeBanner();
    }     // end while

    logAction("User logged out");
    fclose(cfPtr); // fclose closes the file
} // end main

// change PIN
void changePin(void)
{
    FILE *fPtr = fopen("credit.dat", "rb+");
    if (!fPtr)
    {
        printf("Error opening file.\n");
        return;
    }

    fseek(fPtr, 0, SEEK_SET);
    unsigned int storedHash;
    fread(&storedHash, sizeof(unsigned int), 1, fPtr);

    char oldPin[5], newPin[5], confirmPin[5];
    char input[10];
    int attempts = 0;

    while (attempts < MAX_ATTEMPTS)
    {
        printf("Enter current PIN: ");
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("Input error.\n");
            fclose(fPtr);
            return;
        }
        input[strcspn(input, "\n")] = 0;
        if (strlen(input) != 4 || strspn(input, "0123456789") != 4)
        {
            printf("Invalid PIN format.\n");
            attempts++;
            continue;
        }
        strcpy(oldPin, input);

        if (hashPin(oldPin) == storedHash)
        {
            break;
        }
        attempts++;
        printf("Incorrect PIN. Attempts remaining: %d\n", MAX_ATTEMPTS - attempts);
    }

    if (attempts >= MAX_ATTEMPTS)
    {
        printf("Too many failed attempts.\n");
        logAction("Failed PIN change attempts");
        fclose(fPtr);
        return;
    }

    printf("Enter new 4-digit PIN: ");
    if (fgets(input, sizeof(input), stdin) == NULL)
    {
        printf("Input error.\n");
        fclose(fPtr);
        return;
    }
    input[strcspn(input, "\n")] = 0;
    if (strlen(input) != 4 || strspn(input, "0123456789") != 4)
    {
        printf("Invalid PIN format.\n");
        fclose(fPtr);
        return;
    }
    strcpy(newPin, input);

    printf("Confirm new PIN: ");
    if (fgets(input, sizeof(input), stdin) == NULL)
    {
        printf("Input error.\n");
        fclose(fPtr);
        return;
    }
    input[strcspn(input, "\n")] = 0;
    if (strlen(input) != 4 || strspn(input, "0123456789") != 4)
    {
        printf("Invalid PIN format.\n");
        fclose(fPtr);
        return;
    }
    strcpy(confirmPin, input);

    if (strcmp(newPin, confirmPin) != 0)
    {
        printf("PINs do not match.\n");
        fclose(fPtr);
        return;
    }

    unsigned int newHash = hashPin(newPin);
    fseek(fPtr, 0, SEEK_SET);
    fwrite(&newHash, sizeof(unsigned int), 1, fPtr);
    printf("PIN changed successfully.\n");
    logAction("PIN changed");
    fclose(fPtr);
}

// hash function for PIN
unsigned int hashPin(const char *pin)
{
    unsigned int hash = 5381;
    while (*pin)
    {
        hash = ((hash << 5) + hash) + *pin++;
    }
    return hash;
}

// log action to audit file
void logAction(const char *action)
{
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(log, "[%s] %s\n", timestamp, action);
    fclose(log);
}

// initialize default PIN
void initPassword(void)
{
    FILE *fPtr = fopen("credit.dat", "rb+");
    if (!fPtr) return;

    fseek(fPtr, 0, SEEK_SET);
    unsigned int storedHash;
    if (fread(&storedHash, sizeof(unsigned int), 1, fPtr) != 1)
    {
        fseek(fPtr, 0, SEEK_SET);
        unsigned int defaultPin = hashPin("1234");
        fwrite(&defaultPin, sizeof(unsigned int), 1, fPtr);
        printf("Default PIN set to: 1234\n");
        logAction("Default PIN initialized");
    }
    fclose(fPtr);
}

// authenticate user with PIN
int authenticateUser(void)
{
    FILE *fPtr = fopen("credit.dat", "rb+");
    if (!fPtr) return 0;

    fseek(fPtr, 0, SEEK_SET);
    unsigned int storedHash;
    fread(&storedHash, sizeof(unsigned int), 1, fPtr);
    fclose(fPtr);

    char pin[5];
    char input[10];
    int attempts = 0;

    while (attempts < MAX_ATTEMPTS)
    {
        printf("Enter 4-digit PIN: ");
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("Input error.\n");
            continue;
        }
        // Remove newline
        input[strcspn(input, "\n")] = 0;

        if (strlen(input) != 4 || strspn(input, "0123456789") != 4)
        {
            printf("Invalid PIN format. Must be exactly 4 digits.\n");
            attempts++;
            printf("Incorrect PIN. Attempts remaining: %d\n", MAX_ATTEMPTS - attempts);
            continue;
        }

        strcpy(pin, input);

        if (hashPin(pin) == storedHash)
        {
            return 1;
        }

        attempts++;
        printf("Incorrect PIN. Attempts remaining: %d\n", MAX_ATTEMPTS - attempts);
        // Add delay to prevent brute force
        sleep(1);
    }

    logAction("Failed login attempts exceeded");
    return 0;
}

// create formatted text file for printing
void textFile(FILE *readPtr)
{
    FILE *writePtr; // accounts.txt file pointer
    int result;     // used to test whether fread read any bytes
    // create clientData with default information
    struct clientData client = {0, "", "", 0.0};

    // fopen opens the file; exits if file cannot be opened
    if ((writePtr = fopen("accounts.txt", "w")) == NULL)
    {
        puts("File could not be opened.");
    } // end if
    else
    {
        rewind(readPtr); // sets pointer to beginning of file
        fprintf(writePtr, "%-6s%-16s%-11s%10s\n", "Acct", "Last Name", "First Name", "Balance");

        // copy all records from random-access file into text file
        while (!feof(readPtr))
        {
            result = fread(&client, sizeof(struct clientData), 1, readPtr);

            // write single record to text file
            if (result != 0 && client.acctNum != 0)
            {
                fprintf(writePtr, "%-6d%-16s%-11s%10.2f\n", client.acctNum, client.lastName, client.firstName,
                        client.balance);
            } // end if
        }     // end while

        fclose(writePtr); // fclose closes the file
        printf("Account list exported to accounts.txt\n");
        logAction("Exported account list");
    } // end else
} // end function textFile

// update balance in record
void updateRecord(FILE *fPtr)
{
    unsigned int account; // account number
    double transaction;   // transaction amount
    // create clientData with no information
    struct clientData client = {0, "", "", 0.0};
    char input[100];

    // obtain number of account to update
    printf("%s", "Enter account to update ( 1 - 100 ): ");
    if (fgets(input, sizeof(input), stdin) == NULL)
    {
        printf("Input error.\n");
        return;
    }
    input[strcspn(input, "\n")] = 0;
    if (sscanf(input, "%u", &account) != 1 || account < 1 || account > 100)
    {
        printf("Invalid account number.\n");
        return;
    }

    // move file pointer to correct record in file
    fseek(fPtr, (account - 1) * sizeof(struct clientData), SEEK_SET);
    // read record from file
    fread(&client, sizeof(struct clientData), 1, fPtr);
    // display error if account does not exist
    if (client.acctNum == 0)
    {
        printf("Account #%d has no information.\n", account);
    }
    else
    { // update record
        printf("%-6d%-16s%-11s%10.2f\n\n", client.acctNum, client.lastName, client.firstName, client.balance);

        // request transaction amount from user
        printf("%s", "Enter charge ( + ) or payment ( - ): ");
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("Input error.\n");
            return;
        }
        input[strcspn(input, "\n")] = 0;
        if (sscanf(input, "%lf", &transaction) != 1)
        {
            printf("Invalid transaction amount.\n");
            return;
        }

        // check for insufficient funds
        if (transaction < 0 && client.balance + transaction < 0)
        {
            printf("Insufficient funds. Transaction denied.\n");
            logAction("Insufficient funds");
            return;
        }

        client.balance += transaction; // update record balance

        printf("%-6d%-16s%-11s%10.2f\n", client.acctNum, client.lastName, client.firstName, client.balance);

        // move file pointer to correct record in file
        // move back by 1 record length
        fseek(fPtr, -(long)sizeof(struct clientData), SEEK_CUR);
        // write updated record over old record in file
        fwrite(&client, sizeof(struct clientData), 1, fPtr);

        // log the transaction
        char logMsg[100];
        snprintf(logMsg, sizeof(logMsg), "Account %d updated: %.2f", account, transaction);
        logAction(logMsg);
    } // end else
} // end function updateRecord

// delete an existing record
void deleteRecord(FILE *fPtr)
{
    struct clientData client;                       // stores record read from file
    struct clientData blankClient = {0, "", "", 0}; // blank client
    unsigned int accountNum;                        // account number
    char confirm;
    char input[10];

    // obtain number of account to delete
    printf("%s", "Enter account number to delete ( 1 - 100 ): ");
    if (fgets(input, sizeof(input), stdin) == NULL)
    {
        printf("Input error.\n");
        return;
    }
    input[strcspn(input, "\n")] = 0;
    if (sscanf(input, "%u", &accountNum) != 1 || accountNum < 1 || accountNum > 100)
    {
        printf("Invalid account number.\n");
        return;
    }

    // move file pointer to correct record in file
    fseek(fPtr, (accountNum - 1) * sizeof(struct clientData), SEEK_SET);
    // read record from file
    fread(&client, sizeof(struct clientData), 1, fPtr);
    // display error if record does not exist
    if (client.acctNum == 0)
    {
        printf("Account %d does not exist.\n", accountNum);
    } // end if
    else
    {
        // confirm deletion
        printf("Confirm deletion of account #%d (y/n): ", accountNum);
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("Input error.\n");
            return;
        }
        input[strcspn(input, "\n")] = 0;
        if (sscanf(input, " %c", &confirm) != 1)
        {
            printf("Invalid confirmation.\n");
            return;
        }

        if (confirm == 'y' || confirm == 'Y')
        {
            // move file pointer to correct record in file
            fseek(fPtr, (accountNum - 1) * sizeof(struct clientData), SEEK_SET);
            // replace existing record with blank record
            fwrite(&blankClient, sizeof(struct clientData), 1, fPtr);
            printf("Account deleted successfully.\n");

            // log the deletion
            char logMsg[50];
            snprintf(logMsg, sizeof(logMsg), "Account %d deleted", accountNum);
            logAction(logMsg);
        }
        else
        {
            printf("Deletion cancelled.\n");
        }
    } // end else
} // end function deleteRecord

// create and insert record
void newRecord(FILE *fPtr)
{
    // create clientData with default information
    struct clientData client = {0, "", "", 0.0};
    unsigned int accountNum; // account number
    char input[100];

    // obtain number of account to create
    printf("%s", "Enter new account number ( 1 - 100 ): ");
    if (fgets(input, sizeof(input), stdin) == NULL)
    {
        printf("Input error.\n");
        return;
    }
    input[strcspn(input, "\n")] = 0;
    if (sscanf(input, "%u", &accountNum) != 1 || accountNum < 1 || accountNum > 100)
    {
        printf("Invalid account number.\n");
        return;
    }

    // move file pointer to correct record in file
    fseek(fPtr, (accountNum - 1) * sizeof(struct clientData), SEEK_SET);
    // read record from file
    fread(&client, sizeof(struct clientData), 1, fPtr);
    // display error if account already exists
    if (client.acctNum != 0)
    {
        printf("Account #%d already contains information.\n", client.acctNum);
    } // end if
    else
    { // create record
        // user enters last name, first name and balance
        printf("%s", "Enter lastname, firstname, balance\n? ");
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("Input error.\n");
            return;
        }
        input[strcspn(input, "\n")] = 0;
        char lastName[15], firstName[10];
        double balance;
        if (sscanf(input, "%14s %9s %lf", lastName, firstName, &balance) != 3)
        {
            printf("Invalid input format.\n");
            return;
        }

        // prevent negative balance
        if (balance < 0)
        {
            printf("Initial balance cannot be negative. Set to 0.\n");
            balance = 0;
        }

        strcpy(client.lastName, lastName);
        strcpy(client.firstName, firstName);
        client.balance = balance;
        client.acctNum = accountNum;
        // move file pointer to correct record in file
        fseek(fPtr, (client.acctNum - 1) * sizeof(struct clientData), SEEK_SET);
        // insert record in file
        fwrite(&client, sizeof(struct clientData), 1, fPtr);

        // log the new account
        char logMsg[100];
        snprintf(logMsg, sizeof(logMsg), "New account created: %d", accountNum);
        logAction(logMsg);
    } // end else
} // end function newRecord

// enable user to input menu choice
unsigned int enterChoice(void)
{
    unsigned int menuChoice; // variable to store user's choice
    char input[10];

    displayMenu();
    if (fgets(input, sizeof(input), stdin) == NULL)
    {
        return 6; // default to exit on error
    }
    input[strcspn(input, "\n")] = 0;
    if (sscanf(input, "%u", &menuChoice) != 1)
    {
        return 0; // invalid choice
    }
    return menuChoice;
} // end function enterChoice

void clearScreen(void)
{
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void pauseForEnter(void)
{
    char input[10];
    printf("\nPress Enter to return to the main menu...");
    fgets(input, sizeof(input), stdin);
}

void printWelcomeBanner(void)
{
    printf("==============================================\n");
    printf("  Secure Bank Account Management System\n");
    printf("==============================================\n");
    printf("Logged in successfully. Choose an option below.\n\n");
}

void displayMenu(void)
{
    printf("MAIN MENU\n");
    printf("----------------------------------------------\n");
    printf("1) Export account data to accounts.txt\n");
    printf("2) Update an existing account\n");
    printf("3) Change PIN\n");
    printf("4) Add a new account\n");
    printf("5) Delete an account\n");
    printf("6) Exit program\n");
    printf("----------------------------------------------\n");
    printf("> ");
} // end function displayMenu
