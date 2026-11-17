const { Client } = require('pg');

const client = new Client({
  host: '172.16.2.70',
  port: 5432,
  user: 'postgres',
  password: 'abcd123',
  database: 'postgres'
});

client.connect()
  .then(() => client.query('SELECT name, salary FROM employees ORDER BY salary DESC'))
  .then(res => {
    console.log('\n📊 EMPLOYEE SALARY BAR CHART:\n');
    
    const maxSalary = res.rows.reduce((max, row) => Math.max(max, row.salary), 0);
    const barLength = 40;

    res.rows.forEach(row => {
      const value = parseFloat(row.salary) || 0;
      const length = Math.round((value / maxSalary) * barLength);
      const bar = '█'.repeat(length);
      const pad = ' '.repeat(barLength - length);
      console.log(`${row.name.padEnd(15)} | ${bar}${pad} ${value.toFixed(2)}`);
    });

    client.end();
  })
  .catch(err => console.error('Error:', err.message));
