using GraphQL.Types;
using System.Data;
using GraphQL;

namespace VulnerableWebApplication.VLAModel
{
    public class Employee
    {
        /*
        Données des employés de l'entreprise
        */
        public string Id { get; set; }
        public string Name { get; set; }
        public int Age { get; set; }
        public string Address { get; set; }
    }

    public class Creds
    {
        /*
        Login et mots de passe des employés de l'entreprise
        */
        public string User { get; set; }
        public string Passwd { get; set; }
    }

    public class Data
    {
        public static string GetLogPage()
        {
            /*
            Structure des journaux d'événements
            */
            return @"<!doctype html><html lang=""fr""><head><meta charset=""utf-8""><title>Application Logs</title></head><body><h1>Application Logs</h1></body></html>";
        }

        public static DataSet GetDataSet()
        {
            DataTable table = new DataTable();
            table.Columns.Add("User", typeof(string));
            table.Columns.Add("Passwd", typeof(string));
            table.Columns.Add("IsAdmin", typeof(int));

            // Use bcrypt to hash the password and store securely
            table.Rows.Add("user", HashPassword(Environment.GetEnvironmentVariable("USER_PASSWORD")), 0);
            table.Rows.Add("root", HashPassword(Environment.GetEnvironmentVariable("ROOT_PASSWORD")), 1);
            table.Rows.Add("admin", HashPassword(Environment.GetEnvironmentVariable("ADMIN_PASSWORD")), 1);
            table.Rows.Add("Alice", HashPassword(Environment.GetEnvironmentVariable("ALICE_PASSWORD")), 0);
            table.Rows.Add("Bob", HashPassword(Environment.GetEnvironmentVariable("BOB_PASSWORD")), 0);
            table.Rows.Add("Charlie", HashPassword(Environment.GetEnvironmentVariable("CHARLIE_PASSWORD")), 0);
            table.Rows.Add("Diana", HashPassword(Environment.GetEnvironmentVariable("DIANA_PASSWORD")), 0);
            table.Rows.Add("Edward", HashPassword(Environment.GetEnvironmentVariable("EDWARD_PASSWORD")), 0);
            table.Rows.Add("Fiona", HashPassword(Environment.GetEnvironmentVariable("FIONA_PASSWORD")), 0);
            table.Rows.Add("George", HashPassword(Environment.GetEnvironmentVariable("GEORGE_PASSWORD")), 0);
            table.Rows.Add("Hannah", HashPassword(Environment.GetEnvironmentVariable("HANNAH_PASSWORD")), 0);
            table.Rows.Add("Ian", HashPassword(Environment.GetEnvironmentVariable("IAN_PASSWORD")), 0);
            table.Rows.Add("Julia", HashPassword(Environment.GetEnvironmentVariable("JULIA_PASSWORD")), 0);

            var DataSet = new DataSet();
            DataSet.Tables.Add(table);
            return DataSet;
        }

        // Hash the password using bcrypt
        public static string HashPassword(string plainPassword)
        {
            return BCrypt.Net.BCrypt.HashPassword(plainPassword);
        }

        // Verify if the plain password matches the hashed password
        public static bool VerifyPassword(string plainPassword, string hashedPassword)
        {
            return BCrypt.Net.BCrypt.Verify(plainPassword, hashedPassword);
        }

        public static List<Employee> GetEmployees()
        {
            /*
            Contenu de la BDD non relationnelle (Employés)
            */
            List<Employee> Employees = new List<Employee>() {
                new Employee() { Id = "1", Name = "John", Age = 16, Address = "4 rue jean moulin"},
                new Employee() { Id = "42", Name = "Steve",  Age = 21, Address = "3 rue Victor Hugo" },
                new Employee() { Id = "1000", Name = "Bill",  Age = 18, Address = "4 place du 18 juin" },
                new Employee() { Id = "1001", Name = "Alice", Age = 25, Address = "123 rue de la Paix" },
                new Employee() { Id = "1002", Name = "Bob", Age = 30, Address = "456 avenue des Champs-Élysées" },
                new Employee() { Id = "1003", Name = "Charlie", Age = 28, Address = "789 boulevard Saint-Germain" },
                new Employee() { Id = "1004", Name = "Diana", Age = 32, Address = "1010 rue du Faubourg Saint-Honoré" },
                new Employee() { Id = "1005", Name = "Edward", Age = 45, Address = "2020 avenue de la République" },
                new Employee() { Id = "1006", Name = "Fiona", Age = 29, Address = "3030 place de la Concorde" },
                new Employee() { Id = "1007", Name = "George", Age = 35, Address = "4040 rue de Rivoli" },
                new Employee() { Id = "1008", Name = "Hannah", Age = 27, Address = "5050 avenue Montaigne" },
                new Employee() { Id = "1009", Name = "Ian", Age = 40, Address = "6060 rue de la Boétie" },
                new Employee() { Id = "1010", Name = "Julia", Age = 22, Address = "7070 rue de Vaugirard" }
            };
            return Employees;
        }
    }


    /* 
     Classes et Query GraphQL (clients)
     */
    public record Client(int Id, string Name, int Country, int Bank);
    public record Country(int Id, string Name);

    public record Bank(int id, string RIB, string Name);

    public class ClientDetails
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Country { get; set; }
        public string Bank { get; set; }


    }

    public class ClientDetailsType : ObjectGraphType<ClientDetails>
    {
        public ClientDetailsType()
        {
            Field(x => x.Id);
            Field(x => x.Name);
            Field(x => x.Country);
            Field(x => x.Bank); 
        }
    }

    public interface IClientService
    {
        public List<ClientDetails> GetClients();
        public List<ClientDetails> GetClient(int empId);
        public List<ClientDetails> GetClientsByCountry(int Country);
        public List<ClientDetails> GetClientsByBank(int BankId);
    }

    public class ClientService : IClientService
    {
        public ClientService(){}

        private List<Client> Clients = new List<Client>
        {
            new Client(1, "NovaSynergy Solutions", 1,1),
            new Client(2, "EcoVerde Innovations", 1,1),
            new Client(3, "AstraTech Dynamics", 2,1),
            new Client(4, "Luminara Creation", 2,1),
            new Client(5, "ZenithWave Enterprises", 3,1),
        };

        private List<Country> Countrys = new List<Country>
        {
            new Country(1, "France"),
            new Country(2, "Taïwan"),
            new Country(3, "China"),
        };

        private List<Bank> Banks = new List<Bank>
        {
            new Bank(1, "FR1610096000703816856838K74" ,"BdF"),

        };

        public List<ClientDetails> GetClients()
        {
            return Clients.Select(emp => new ClientDetails
            {
                Id = emp.Id,
                Name = emp.Name,
                Country = Countrys.First(d => d.Id == emp.Country).Name,
            }).ToList();
        }

        public List<ClientDetails> GetClient(int empId)
        {
            return Clients.Where(emp => emp.Id == empId).Select(emp => new ClientDetails
            {
                Id = emp.Id,
                Name = emp.Name,
                Country = Countrys.First(d => d.Id == emp.Country).Name,
            }).ToList();
        }


        public List<ClientDetails> GetClientsByCountry(int CountryId)
        {
            return Clients.Where(emp => emp.Country == CountryId).Select(emp => new ClientDetails
            {
                Id = emp.Id,
                Name = emp.Name,
                Country = Countrys.First(d => d.Id == CountryId).Name,
            }).ToList();
        }


        public List<ClientDetails> GetClientsByBank(int BankId)
        {
            return Clients.Where(emp => emp.Bank == BankId).Select(emp => new ClientDetails
            {
                Id = emp.Id,
                Name = emp.Name,
                Bank = Banks.First(b => b.id == BankId).RIB,
            }).ToList();
        }
    }

    public class ClientQuery : ObjectGraphType
    {
        public ClientQuery(IClientService ClientService)
        {

            Field<ListGraphType<ClientDetailsType>>(
                "Clients",
                resolve: context => ClientService.GetClients()
            );

            Field<ListGraphType<ClientDetailsType>>(
                "Client",
                arguments: new QueryArguments(new QueryArgument<IntGraphType> { Name = "Id" }),
                resolve: context => ClientService.GetClient(context.GetArgument<int>("Id"))
            );

            Field<ListGraphType<ClientDetailsType>>(
                "ClientsByCountry",
                arguments: new QueryArguments(new QueryArgument<IntGraphType> { Name = "CountryId" }),
                resolve: context => ClientService.GetClientsByCountry(context.GetArgument<int>("CountryId"))
            );

            Field<ListGraphType<ClientDetailsType>>(
                "ClientsByBank",
                arguments: new QueryArguments(new QueryArgument<IntGraphType> { Name = "Bank" }),
                resolve: context => ClientService.GetClientsByBank(context.GetArgument<int>("Bank"))
            );
        }
    }

    public class ClientDetailsSchema : Schema
    {
        public ClientDetailsSchema(IServiceProvider serviceProvider) : base(serviceProvider)
        {
            Query = serviceProvider.GetRequiredService<ClientQuery>();
        }
    }
}

