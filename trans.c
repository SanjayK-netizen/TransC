// Bank-account program reads a random-access file sequentially,
// updates data already written to the file, creates new data to
// be placed in the file, and deletes data previously in the file.
// Enhanced with: Security (PIN auth), Multi-currency, Audit logging
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define MAX_PIN_ATTEMPTS 3
#define MAX_CURRENCIES 5
#define LOG_FILE "audit.log"

typedef struct {
    char code[4];
    char name[20];
    double rateToUSD;
} Currency;

static const Currency currencies[MAX_CURRENCIES] = {
    {"USD", "US Dollar", 1.0},
    {"EUR", "Euro", 1.08},
    {"GBP", "British Pound", 1.27},
    {"JPY", "Japanese Yen", 0.0067},
    {"INR", "Indian Rupee", 0.012}
};

typedef struct {
    unsigned int acctNum;
    char currency[4];
    int locked;
    unsigned int failedAttempts;
} AccountMeta;

struct clientData
{
    unsigned int acctNum; // account number
    char lastName[15];    // account last name
    char firstName[10];   // account first name
    double balance;       // account balance
};

unsigned int enterChoice(void);
void textFile(FILE *readPtr);
void updateRecord(FILE *fPtr);
void newRecord(FILE *fPtr);
void deleteRecord(FILE *fPtr);
void convertCurrency(FILE *fPtr);
void changePin(FILE *fPtr);
int authenticateUser(FILE *fPtr);
void logAction(const char *action);
unsigned int hashPin(const char *pin);
void initPassword(FILE *fPtr);
void loadAccountMeta(FILE *fPtr, AccountMeta *meta, int count);
void saveAccountMeta(FILE *fPtr, AccountMeta *meta, int count);
const char* getCurrencyName(const char *code);

int main(int argc, char *argv[])
{
    FILE *cfPtr;
    unsigned int choice;

    if ((cfPtr = fopen("credit.dat", "rb+")) == NULL) {
        if ((cfPtr = fopen("credit.dat", "wb")) != NULL) {
            printf("Created new credit.dat file.\n");
        } else {
            printf("%s: File could not be created.\n", argv[0]);
            exit(-1);
        }
    }

    initPassword(cfPtr);

    if (!authenticateUser(cfPtr)) {
        printf("Access denied. Exiting.\n");
        fclose(cfPtr);
        exit(-1);
    }

    while ((choice = enterChoice()) != 8) {
        switch (choice) {
        case 1:
            textFile(cfPtr);
            break;
        case 2:
            updateRecord(cfPtr);
            break;
        case 3:
            newRecord(cfPtr);
            break;
        case 4:
            deleteRecord(cfPtr);
            break;
        case 5:
            convertCurrency(cfPtr);
            break;
        case 6:
            changePin(cfPtr);
            break;
        case 7:
            textFile(cfPtr);
            break;
        default:
            puts("Incorrect choice");
            break;
        }
    }

    logAction("User logged out");
    fclose(cfPtr);
    printf("Goodbye!\n");
    return 0;
}

unsigned int hashPin(const char *pin) {
    unsigned int hash = 5381;
    while (*pin) {
        hash = ((hash << 5) + hash) + *pin++;
    }
    return hash;
}

void initPassword(FILE *fPtr) {
    fseek(fPtr, 0, SEEK_SET);
    unsigned int storedHash;
    if (fread(&storedHash, sizeof(unsigned int), 1, fPtr) != 1) {
        fseek(fPtr, 0, SEEK_SET);
        unsigned int defaultPin = hashPin("1234");
        fwrite(&defaultPin, sizeof(unsigned int), 1, fPtr);
        printf("Default PIN set to: 1234\n");
        logAction("Default PIN initialized");
    }
}

int authenticateUser(FILE *fPtr) {
    fseek(fPtr, 0, SEEK_SET);
    unsigned int storedHash;
    fread(&storedHash, sizeof(unsigned int), 1, fPtr);

    char pin[5];
    int attempts = 0;

    while (attempts < MAX_PIN_ATTEMPTS) {
        printf("Enter 4-digit PIN: ");
        scanf("%4s", pin);

        if (strlen(pin) != 4 || !isdigit(pin[0]) || !isdigit(pin[1]) || 
            !isdigit(pin[2]) || !isdigit(pin[3])) {
            printf("Invalid PIN format. Must be 4 digits.\n");
            continue;
        }

        if (hashPin(pin) == storedHash) {
            logAction("Successful login");
            return 1;
        }

        attempts++;
        printf("Incorrect PIN. Attempts remaining: %d\n", MAX_PIN_ATTEMPTS - attempts);
    }

    logAction("Failed login attempts exceeded");
    return 0;
}

void changePin(FILE *fPtr) {
    char oldPin[5], newPin[5], confirmPin[5];
    
    printf("Enter current PIN: ");
    scanf("%4s", oldPin);
    
    fseek(fPtr, 0, SEEK_SET);
    unsigned int storedHash;
    fread(&storedHash, sizeof(unsigned int), 1, fPtr);
    
    if (hashPin(oldPin) != storedHash) {
        printf("Incorrect current PIN.\n");
        return;
    }
    
    printf("Enter new 4-digit PIN: ");
    scanf("%4s", newPin);
    
    if (strlen(newPin) != 4 || !isdigit(newPin[0])) {
        printf("PIN must be 4 digits.\n");
        return;
    }
    
    printf("Confirm new PIN: ");
    scanf("%4s", confirmPin);
    
    if (strcmp(newPin, confirmPin) != 0) {
        printf("PINs do not match.\n");
        return;
    }
    
    fseek(fPtr, 0, SEEK_SET);
    unsigned int newHash = hashPin(newPin);
    fwrite(&newHash, sizeof(unsigned int), 1, fPtr);
    
    logAction("PIN changed successfully");
    printf("PIN changed successfully.\n");
}

void logAction(const char *action) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(log, "[%s] %s\n", timestamp, action);
    fclose(log);
}

const char* getCurrencyName(const char *code) {
    for (int i = 0; i < MAX_CURRENCIES; i++) {
        if (strcmp(currencies[i].code, code) == 0) {
            return currencies[i].name;
        }
    }
    return "Unknown";
}

void loadAccountMeta(FILE *fPtr, AccountMeta *meta, int count) {
    FILE *metaFile = fopen("accounts.meta", "rb");
    if (metaFile) {
        fread(meta, sizeof(AccountMeta), count, metaFile);
        fclose(metaFile);
    } else {
        for (int i = 0; i < count; i++) {
            meta[i].acctNum = 0;
            meta[i].currency[0] = '\0';
            meta[i].locked = 0;
            meta[i].failedAttempts = 0;
        }
    }
}

void saveAccountMeta(FILE *fPtr, AccountMeta *meta, int count) {
    FILE *metaFile = fopen("accounts.meta", "wb");
    if (metaFile) {
        fwrite(meta, sizeof(AccountMeta), count, metaFile);
        fclose(metaFile);
    }
}

void textFile(FILE *readPtr)
{
    FILE *writePtr;
    int result;
    struct clientData client = {0, "", "", 0.0};
    AccountMeta meta[100];
    loadAccountMeta(readPtr, meta, 100);

    if ((writePtr = fopen("accounts.txt", "w")) == NULL) {
        puts("File could not be opened.");
    } else {
        rewind(readPtr);
        fprintf(writePtr, "%-6s%-16s%-11s%10s %s\n", "Acct", "Last Name", "First Name", "Balance", "Currency");

        while (!feof(readPtr)) {
            result = fread(&client, sizeof(struct clientData), 1, readPtr);
            if (result != 0 && client.acctNum != 0) {
                fprintf(writePtr, "%-6d%-16s%-11s%10.2f [%s]\n", 
                    client.acctNum, client.lastName, client.firstName,
                    client.balance, meta[client.acctNum - 1].currency);
            }
        }
        fclose(writePtr);
        printf("Account list exported to accounts.txt\n");
        logAction("Exported account list");
    }
}

void updateRecord(FILE *fPtr)
{
    unsigned int account;
    double transaction;
    struct clientData client = {0, "", "", 0.0};
    AccountMeta meta[100];
    loadAccountMeta(fPtr, meta, 100);

    printf("Enter account to update (1 - 100): ");
    scanf("%d", &account);

    fseek(fPtr, (account - 1) * sizeof(struct clientData), SEEK_SET);
    fread(&client, sizeof(struct clientData), 1, fPtr);

    if (client.acctNum == 0) {
        printf("Account #%d has no information.\n", account);
    } else if (meta[account - 1].locked) {
        printf("Account is locked. Contact administrator.\n");
    } else {
        printf("%-6d%-16s%-11s%10.2f [%s]\n\n", 
            client.acctNum, client.lastName, client.firstName, 
            client.balance, meta[account - 1].currency);

        printf("Enter charge (+) or payment (-): ");
        scanf("%lf", &transaction);

        if (transaction < 0 && client.balance + transaction < 0) {
            printf("Insufficient funds. Transaction denied.\n");
            logAction("Insufficient funds");
            return;
        }

        client.balance += transaction;
        printf("%-6d%-16s%-11s%10.2f\n", 
            client.acctNum, client.lastName, client.firstName, client.balance);

        fseek(fPtr, - (long) sizeof(struct clientData), SEEK_CUR);
        fwrite(&client, sizeof(struct clientData), 1, fPtr);

        char logMsg[100];
        snprintf(logMsg, sizeof(logMsg), "Account %d updated: %.2f", account, transaction);
        logAction(logMsg);
    }
}

void deleteRecord(FILE *fPtr)
{
    struct clientData client, blankClient = {0, "", "", 0};
    AccountMeta meta[100];
    loadAccountMeta(fPtr, meta, 100);
    unsigned int accountNum;

    printf("Enter account number to delete (1 - 100): ");
    scanf("%d", &accountNum);

    fseek(fPtr, (accountNum - 1) * sizeof(struct clientData), SEEK_SET);
    fread(&client, sizeof(struct clientData), 1, fPtr);

    if (client.acctNum == 0) {
        printf("Account %d does not exist.\n", accountNum);
    } else {
        char confirm;
        printf("Confirm deletion of account %d? (y/n): ", accountNum);
        scanf(" %c", &confirm);

        if (confirm == 'y' || confirm == 'Y') {
            fseek(fPtr, - (long) sizeof(struct clientData), SEEK_CUR);
            fwrite(&blankClient, sizeof(struct clientData), 1, fPtr);
            
            meta[accountNum - 1].currency[0] = '\0';
            meta[accountNum - 1].locked = 0;
            saveAccountMeta(fPtr, meta, 100);
            
            printf("Account deleted successfully.\n");
            logAction("Account deleted");
        }
    }
}

void newRecord(FILE *fPtr)
{
    struct clientData client = {0, "", "", 0.0};
    AccountMeta meta[100];
    unsigned int accountNum;
    int currencyChoice;

    loadAccountMeta(fPtr, meta, 100);

    printf("Enter new account number (1 - 100): ");
    scanf("%d", &accountNum);

    fseek(fPtr, (accountNum - 1) * sizeof(struct clientData), SEEK_SET);
    fread(&client, sizeof(struct clientData), 1, fPtr);

    if (client.acctNum != 0) {
        printf("Account #%d already contains information.\n", client.acctNum);
    } else {
        printf("Available currencies:\n");
        for (int i = 0; i < MAX_CURRENCIES; i++) {
            printf("  %d. %s (%s)\n", i + 1, currencies[i].name, currencies[i].code);
        }
        printf("Select currency (1-%d) [default 1-USD]: ", MAX_CURRENCIES);
        scanf("%d", &currencyChoice);

        if (currencyChoice < 1 || currencyChoice > MAX_CURRENCIES) {
            currencyChoice = 1;
        }

        strcpy(meta[accountNum - 1].currency, currencies[currencyChoice - 1].code);
        meta[accountNum - 1].locked = 0;
        meta[accountNum - 1].failedAttempts = 0;

        printf("Enter lastname, firstname, balance\n? ");
        scanf("%14s%9s%lf", client.lastName, client.firstName, &client.balance);

        if (client.balance < 0) {
            printf("Initial balance cannot be negative. Set to 0.\n");
            client.balance = 0;
        }

        client.acctNum = accountNum;
        fseek(fPtr, - (long) sizeof(struct clientData), SEEK_CUR);
        fwrite(&client, sizeof(struct clientData), 1, fPtr);
        saveAccountMeta(fPtr, meta, 100);

        char logMsg[100];
        snprintf(logMsg, sizeof(logMsg), "New account created: %d in %s", accountNum, meta[accountNum - 1].currency);
        logAction(logMsg);
    }
}

void convertCurrency(FILE *fPtr)
{
    unsigned int account;
    struct clientData client = {0, "", "", 0.0};
    AccountMeta meta[100];
    int targetCurrency;
    double convertedAmount;

    loadAccountMeta(fPtr, meta, 100);

    printf("Enter account to convert (1 - 100): ");
    scanf("%d", &account);

    fseek(fPtr, (account - 1) * sizeof(struct clientData), SEEK_SET);
    fread(&client, sizeof(struct clientData), 1, fPtr);

    if (client.acctNum == 0) {
        printf("Account #%d has no information.\n", account);
        return;
    }

    char currentCurrency[4];
    strcpy(currentCurrency, meta[account - 1].currency);
    if (currentCurrency[0] == '\0') {
        strcpy(currentCurrency, "USD");
    }

    printf("Current balance: %.2f %s (%s)\n", 
           client.balance, currentCurrency, getCurrencyName(currentCurrency));

    printf("Convert to:\n");
    for (int i = 0; i < MAX_CURRENCIES; i++) {
        printf("  %d. %s (%s)\n", i + 1, currencies[i].name, currencies[i].code);
    }
    printf("Select target currency (1-%d): ", MAX_CURRENCIES);
    scanf("%d", &targetCurrency);

    if (targetCurrency < 1 || targetCurrency > MAX_CURRENCIES) {
        printf("Invalid selection.\n");
        return;
    }

    int fromIdx = 0, toIdx = targetCurrency - 1;
    for (int i = 0; i < MAX_CURRENCIES; i++) {
        if (strcmp(currencies[i].code, currentCurrency) == 0) {
            fromIdx = i;
            break;
        }
    }

    double amountInUSD = client.balance * currencies[fromIdx].rateToUSD;
    convertedAmount = amountInUSD / currencies[toIdx].rateToUSD;

    printf("\nConverted balance: %.2f %s (%s)\n", 
           convertedAmount, currencies[toIdx].code, currencies[toIdx].name);
    printf("Exchange rate: 1 %s = %.4f %s\n", 
           currentCurrency, currencies[toIdx].rateToUSD / currencies[fromIdx].rateToUSD,
           currencies[toIdx].code);

    char confirm;
    printf("\nUpdate account with new currency? (y/n): ");
    scanf(" %c", &confirm);

    if (confirm == 'y' || confirm == 'Y') {
        client.balance = convertedAmount;
        strcpy(meta[account - 1].currency, currencies[toIdx].code);
        
        fseek(fPtr, - (long) sizeof(struct clientData), SEEK_CUR);
        fwrite(&client, sizeof(struct clientData), 1, fPtr);
        saveAccountMeta(fPtr, meta, 100);

        char logMsg[100];
        snprintf(logMsg, sizeof(logMsg), "Account %d currency converted to %s", account, currencies[toIdx].code);
        logAction(logMsg);
        printf("Account updated successfully.\n");
    }
}

unsigned int enterChoice(void)
{
    unsigned int menuChoice;
    printf("\nEnter your choice\n"
           "1 - store a formatted text file of accounts called\n"
           "    \"accounts.txt\" for printing\n"
           "2 - update an account\n"
           "3 - add a new account\n"
           "4 - delete an account\n"
           "5 - convert currency\n"
           "6 - change PIN\n"
           "7 - view accounts\n"
           "8 - end program\n? ");

    scanf("%u", &menuChoice);
    return menuChoice;
}
